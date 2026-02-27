import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple

from fastapi import FastAPI
from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    walk_cmd,  # GETNEXT-style walk (like snmpwalk)
)

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("printer-discovery")

app = FastAPI(title="Printer Discovery", version="1.2.4")

# -------------------------
# Config (env)
# -------------------------
SUBNET = os.getenv("SUBNET", "10.1.10.0/24")

SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "120"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "0.25"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))

ENABLE_MDNS = os.getenv("ENABLE_MDNS", "true").lower() == "true"
ENABLE_SNMP = os.getenv("ENABLE_SNMP", "true").lower() == "true"

SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
SNMP_PORT = int(os.getenv("SNMP_PORT", "161"))
SNMP_TIMEOUT = float(os.getenv("SNMP_TIMEOUT", "1.0"))
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "0"))

# Limits to prevent SNMP work from "stalling" discovery
SNMP_CONCURRENCY = int(os.getenv("SNMP_CONCURRENCY", "20"))
SNMP_ENRICH_TIMEOUT = float(os.getenv("SNMP_ENRICH_TIMEOUT", "3.0"))  # seconds
SNMP_ENRICH_COOLDOWN = int(os.getenv("SNMP_ENRICH_COOLDOWN", "300"))  # seconds
SNMP_MAX_IFPHYS_ROWS = int(os.getenv("SNMP_MAX_IFPHYS_ROWS", "25"))   # max rows to inspect

QUALIFY_PORTS = [int(p) for p in os.getenv("QUALIFY_PORTS", "9100,631,515").split(",") if p.strip()]
WEB_PORTS = [int(p) for p in os.getenv("WEB_PORTS", "443,80").split(",") if p.strip()]

# OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_PRT_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"          # Printer-MIB serial
OID_ENT_SERIAL_1 = "1.3.6.1.2.1.47.1.1.1.1.11.1"      # ENTITY-MIB serial (some devices)
OID_IF_PHYS_ADDR_BASE = "1.3.6.1.2.1.2.2.1.6"         # IF-MIB MAC table

MAIN_LOOP: Optional[asyncio.AbstractEventLoop] = None

# -------------------------
# Data model
# -------------------------
@dataclass
class Printer:
    name: str
    ip: str
    web: Optional[str] = None
    serial: Optional[str] = None
    mac: Optional[str] = None
    sys_descr: Optional[str] = None
    source: str = "scan"  # scan|mdns|both
    last_seen: float = 0.0
    print_ports: Optional[List[int]] = None

    @property
    def details(self) -> str:
        return " | ".join(
            [
                f"IP: {self.ip}",
                f"MAC: {self.mac or '—'}",
                f"Serial: {self.serial or '—'}",
            ]
        )


PRINTERS: Dict[str, Printer] = {}
LAST_SCAN: float = 0.0

# SNMP enrichment control
_snmp_sem = asyncio.Semaphore(SNMP_CONCURRENCY)
_enrich_in_flight: Set[str] = set()
_enrich_next_allowed: Dict[str, float] = {}


def _now() -> float:
    return time.time()


def _format_mac(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if len(raw) > 6:
        raw = raw[-6:]
    if len(raw) != 6:
        return None
    if all(b == 0x00 for b in raw):
        return None
    # ignore multicast MACs
    if raw[0] & 0x01:
        return None
    return ":".join(f"{b:02X}" for b in raw)


def _compact_hex(s: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", s or "").lower()


def _brother_mac_from_sysname(sys_name: str) -> Optional[str]:
    # Brother sysName often looks like: BRWD8B32F1E6A9C
    m = re.search(r"\bBRW([0-9A-Fa-f]{12})\b", sys_name or "")
    if not m:
        return None
    h = m.group(1).lower()
    return ":".join(h[i:i+2].upper() for i in range(0, 12, 2))


async def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _open_print_ports(ip: str) -> List[int]:
    checks = await asyncio.gather(
        *[_tcp_probe(ip, p, CONNECT_TIMEOUT) for p in QUALIFY_PORTS],
        return_exceptions=True,
    )
    return [p for p, ok in zip(QUALIFY_PORTS, checks) if ok is True]


async def _pick_web_url(ip: str) -> str:
    for p in WEB_PORTS:
        if await _tcp_probe(ip, p, CONNECT_TIMEOUT):
            if p == 443:
                return f"https://{ip}/"
            if p == 80:
                return f"http://{ip}/"
            scheme = "https" if p == 443 else "http"
            return f"{scheme}://{ip}:{p}/"
    return f"http://{ip}/"


def _merge_printer(p: Printer) -> None:
    existing = PRINTERS.get(p.ip)
    if not existing:
        PRINTERS[p.ip] = p
        return

    existing.last_seen = max(existing.last_seen, p.last_seen)
    existing.source = "both" if existing.source != p.source else existing.source
    existing.name = existing.name or p.name
    existing.web = existing.web or p.web
    existing.serial = existing.serial or p.serial
    existing.mac = existing.mac or p.mac
    existing.sys_descr = existing.sys_descr or p.sys_descr
    if not existing.print_ports and p.print_ports:
        existing.print_ports = p.print_ports


# -------------------------
# SNMP helpers
# -------------------------
async def snmp_get_map(ip: str, oids: List[str]) -> Dict[str, str]:
    if not ENABLE_SNMP:
        return {}

    snmpEngine = SnmpEngine()
    auth = CommunityData(SNMP_COMMUNITY, mpModel=1)  # v2c
    target = await UdpTransportTarget.create((ip, SNMP_PORT), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
    ctx = ContextData()

    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    iterator = get_cmd(snmpEngine, auth, target, ctx, *var_binds)

    try:
        errorIndication, errorStatus, errorIndex, outVarBinds = await iterator
        if errorIndication or errorStatus:
            return {}
        out: Dict[str, str] = {}
        for req_oid, vb in zip(oids, outVarBinds):
            out[req_oid] = vb[1].prettyPrint()
        return out
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


async def snmp_get_first_mac(ip: str) -> Optional[str]:
    """
    Walk IF-MIB ifPhysAddress using GETNEXT-style walk_cmd and return the first valid MAC.
    This mirrors the behavior of snmpwalk closely. walk_cmd stops when it leaves subtree. :contentReference[oaicite:1]{index=1}
    """
    if not ENABLE_SNMP:
        return None

    snmpEngine = SnmpEngine()
    auth = CommunityData(SNMP_COMMUNITY, mpModel=1)
    target = await UdpTransportTarget.create((ip, SNMP_PORT), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
    ctx = ContextData()
    base = ObjectType(ObjectIdentity(OID_IF_PHYS_ADDR_BASE))

    rows = 0
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
            snmpEngine,
            auth,
            target,
            ctx,
            base,
            lexicographicMode=False,
            lookupMib=False,
        ):
            if errorIndication or errorStatus:
                return None

            for vb in varBinds:
                val = vb[1]
                try:
                    raw = val.asOctets() if hasattr(val, "asOctets") else bytes(val)
                except Exception:
                    raw = b""
                mac = _format_mac(raw)
                if mac:
                    return mac

            rows += 1
            if rows >= SNMP_MAX_IFPHYS_ROWS:
                return None
        return None
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


async def snmp_enrich_ip(ip: str) -> None:
    """
    Enrich an existing PRINTERS[ip] entry with SNMP sysName/sysDescr/serial/MAC.
    Runs with concurrency limits + cooldown so discovery doesn't stall.
    """
    if not ENABLE_SNMP:
        return

    now = _now()
    if now < _enrich_next_allowed.get(ip, 0):
        return
    if ip in _enrich_in_flight:
        return

    _enrich_in_flight.add(ip)
    _enrich_next_allowed[ip] = now + SNMP_ENRICH_COOLDOWN

    try:
        async with _snmp_sem:
            try:
                await asyncio.wait_for(_snmp_enrich_core(ip), timeout=SNMP_ENRICH_TIMEOUT)
            except asyncio.TimeoutError:
                log.debug("SNMP enrich timeout for %s", ip)
    finally:
        _enrich_in_flight.discard(ip)


async def _snmp_enrich_core(ip: str) -> None:
    got = await snmp_get_map(ip, [OID_SYS_NAME, OID_SYS_DESCR, OID_PRT_SERIAL, OID_ENT_SERIAL_1])

    sys_name = (got.get(OID_SYS_NAME) or "").strip() or None
    sys_descr = (got.get(OID_SYS_DESCR) or "").strip() or None
    serial = (got.get(OID_PRT_SERIAL) or got.get(OID_ENT_SERIAL_1) or "").strip() or None

    mac = None

    # Fast path: Brother sysName encodes the MAC
    if sys_name:
        mac = _brother_mac_from_sysname(sys_name)

    # Generic path: IF-MIB table (first valid MAC)
    if not mac:
        mac = await snmp_get_first_mac(ip)

    p = PRINTERS.get(ip)
    if not p:
        return

    # Update-in-place (keep existing fields if already populated)
    if sys_name and not p.name:
        p.name = sys_name
    elif sys_name:
        # Prefer SNMP sysName as authoritative name if current is just IP
        if p.name == ip:
            p.name = sys_name

    if sys_descr and not p.sys_descr:
        p.sys_descr = sys_descr

    if serial and not p.serial:
        p.serial = serial

    if mac and not p.mac:
        p.mac = mac


# -------------------------
# mDNS discovery (thread-safe scheduling)
# -------------------------
class MdnsListener(ServiceListener):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._schedule(zc, type_, name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._schedule(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def _schedule(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Zeroconf ServiceBrowser callbacks run in its dedicated thread; schedule on main loop
        fut = asyncio.run_coroutine_threadsafe(self._handle(zc, type_, name), self.loop)
        fut.add_done_callback(lambda f: f.exception() if (not f.cancelled()) else None)

    async def _handle(self, zc: Zeroconf, type_: str, name: str) -> None:
        def _get():
            return zc.get_service_info(type_, name, timeout=1500)

        info = await asyncio.to_thread(_get)
        if not info or not info.addresses:
            return

        ip = None
        for addr in info.addresses:
            if len(addr) == 4:
                ip = socket.inet_ntoa(addr)
                break
        if not ip:
            return

        display = name.split(".")[0] if name else ip
        mdns_port = int(info.port) if info.port else None
        print_ports = [mdns_port] if (mdns_port in QUALIFY_PORTS) else None

        web = await _pick_web_url(ip)

        # MERGE FIRST (so it shows up immediately)
        p = Printer(
            name=display,
            ip=ip,
            web=web,
            source="mdns",
            last_seen=_now(),
            print_ports=print_ports,
        )
        _merge_printer(p)

        # ENRICH IN BACKGROUND
        asyncio.create_task(snmp_enrich_ip(ip))


async def mdns_task():
    if not ENABLE_MDNS or MAIN_LOOP is None:
        return

    zc = Zeroconf(ip_version=IPVersion.V4Only)
    listener = MdnsListener(MAIN_LOOP)

    types = ["_printer._tcp.local.", "_ipp._tcp.local.", "_ipps._tcp.local."]
    browsers = [ServiceBrowser(zc, t, listener) for t in types]

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        try:
            zc.close()
        except Exception:
            pass


# -------------------------
# Subnet scan (qualify) + background SNMP enrich
# -------------------------
async def scan_subnet_once():
    global LAST_SCAN

    net = ipaddress.ip_network(SUBNET, strict=False)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def scan_ip(ip: str):
        async with sem:
            print_ports = await _open_print_ports(ip)
            if not print_ports:
                return

            web = await _pick_web_url(ip)

            # MERGE FIRST
            p = Printer(
                name=ip,
                ip=ip,
                web=web,
                source="scan",
                last_seen=_now(),
                print_ports=print_ports,
            )
            _merge_printer(p)

            # ENRICH IN BACKGROUND
            asyncio.create_task(snmp_enrich_ip(ip))

    tasks = [asyncio.create_task(scan_ip(str(h))) for h in net.hosts()]
    await asyncio.gather(*tasks)
    LAST_SCAN = _now()


async def scan_loop():
    while True:
        try:
            await scan_subnet_once()
        except Exception as e:
            log.warning("scan loop error: %s", e)
        await asyncio.sleep(SCAN_INTERVAL)


# -------------------------
# API
# -------------------------
@app.get("/health")
def health():
    return {
        "ok": True,
        "subnet": SUBNET,
        "last_scan": LAST_SCAN,
        "qualify_ports": QUALIFY_PORTS,
        "web_ports": WEB_PORTS,
        "enable_mdns": ENABLE_MDNS,
        "enable_snmp": ENABLE_SNMP,
        "snmp_concurrency": SNMP_CONCURRENCY,
        "snmp_enrich_timeout": SNMP_ENRICH_TIMEOUT,
        "snmp_enrich_cooldown": SNMP_ENRICH_COOLDOWN,
    }


@app.get("/api/printers")
def api_printers():
    items = sorted(PRINTERS.values(), key=lambda p: (p.name.lower(), p.ip))
    return {
        "subnet": SUBNET,
        "last_scan": LAST_SCAN,
        "count": len(items),
        "printers": [{**asdict(p), "details": p.details} for p in items],
    }


@app.on_event("startup")
async def startup():
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    asyncio.create_task(scan_loop())
    asyncio.create_task(mdns_task())
