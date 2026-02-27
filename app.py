import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

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
    bulk_walk_cmd,
)

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("printer-discovery")

app = FastAPI(title="Printer Discovery", version="1.2.2")

# -------------------------
# Config (env)
# -------------------------
SUBNET = os.getenv("SUBNET", "10.1.10.0/24")

SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "120"))  # seconds
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "0.25"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))

ENABLE_MDNS = os.getenv("ENABLE_MDNS", "true").lower() == "true"
ENABLE_SNMP = os.getenv("ENABLE_SNMP", "true").lower() == "true"

SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
SNMP_PORT = int(os.getenv("SNMP_PORT", "161"))
SNMP_TIMEOUT = float(os.getenv("SNMP_TIMEOUT", "1.0"))
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "0"))

# Only these ports qualify a device as a printer
QUALIFY_PORTS = [int(p) for p in os.getenv("QUALIFY_PORTS", "9100,631,515").split(",") if p.strip()]
# Only used to build a clickable link (do NOT qualify)
WEB_PORTS = [int(p) for p in os.getenv("WEB_PORTS", "443,80").split(",") if p.strip()]

# OIDs (best-effort)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Printer-MIB prtGeneralSerialNumber.1
OID_PRT_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"
# ENTITY-MIB entPhysicalSerialNum.1 (some vendors)
OID_ENT_SERIAL_1 = "1.3.6.1.2.1.47.1.1.1.1.11.1"

# IF-MIB ifPhysAddress.<ifIndex>
OID_IF_PHYS_ADDR_BASE = "1.3.6.1.2.1.2.2.1.6"

# Main Uvicorn loop (set at startup)
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


def _now() -> float:
    return time.time()


def _format_mac(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if all(b == 0x00 for b in raw):
        return None
    # ignore multicast MACs (least significant bit of first octet set)
    if raw[0] & 0x01:
        return None
    return ":".join(f"{b:02X}" for b in raw)


def _mac_to_compact(mac: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()


def _extract_mdns_mac_hint(name: str) -> Optional[str]:
    # Examples: "Brother HL-L2460DW [94ddf86a9634]" -> "94ddf86a9634"
    m = re.search(r"\[([0-9a-fA-F]{8,16})\]", name or "")
    return m.group(1).lower() if m else None


def _choose_best_mac(candidates: List[str], hint: Optional[str]) -> Optional[str]:
    if not candidates:
        return None
    if hint:
        for mac in candidates:
            if _mac_to_compact(mac).endswith(hint) or hint in _mac_to_compact(mac):
                return mac
    return candidates[0]


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
    """
    SNMP GET multiple OIDs (v2c). Returns dict mapping *requested oid* -> value.
    """
    if not ENABLE_SNMP:
        return {}

    snmpEngine = SnmpEngine()
    auth = CommunityData(SNMP_COMMUNITY, mpModel=1)  # v2c
    target = await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=SNMP_TIMEOUT,
        retries=SNMP_RETRIES,
    )
    ctx = ContextData()

    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    iterator = get_cmd(snmpEngine, auth, target, ctx, *var_binds)

    try:
        errorIndication, errorStatus, errorIndex, outVarBinds = await iterator
        if errorIndication or errorStatus:
            return {}

        out: Dict[str, str] = {}
        # Map values back to the requested OIDs in order
        for req_oid, vb in zip(oids, outVarBinds):
            out[req_oid] = vb[1].prettyPrint()
        return out
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


async def snmp_walk_macs(ip: str) -> List[str]:
    """
    Walk IF-MIB ifPhysAddress and return list of non-empty MACs.
    """
    if not ENABLE_SNMP:
        return []

    snmpEngine = SnmpEngine()
    auth = CommunityData(SNMP_COMMUNITY, mpModel=1)  # v2c
    target = await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=SNMP_TIMEOUT,
        retries=SNMP_RETRIES,
    )
    ctx = ContextData()
    base = ObjectType(ObjectIdentity(OID_IF_PHYS_ADDR_BASE))

    macs: List[str] = []
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            snmpEngine,
            auth,
            target,
            ctx,
            0,
            25,
            base,
            lexicographicMode=False,
            lookupMib=False,
        ):
            if errorIndication or errorStatus:
                return []

            for vb in varBinds:
                val = vb[1]
                try:
                    raw = val.asOctets() if hasattr(val, "asOctets") else bytes(val)
                except Exception:
                    raw = b""
                mac = _format_mac(raw)
                if mac and mac not in macs:
                    macs.append(mac)
        return macs
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


async def snmp_enrich(ip: str, name_hint: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Returns (sys_name, sys_descr, serial, mac)
    """
    if not ENABLE_SNMP:
        return None, None, None, None

    try:
        got = await snmp_get_map(ip, [OID_SYS_NAME, OID_SYS_DESCR, OID_PRT_SERIAL, OID_ENT_SERIAL_1])

        sys_name = got.get(OID_SYS_NAME)
        sys_descr = got.get(OID_SYS_DESCR)

        serial = (got.get(OID_PRT_SERIAL) or got.get(OID_ENT_SERIAL_1) or "").strip() or None

        mac_candidates = await snmp_walk_macs(ip)
        mac = _choose_best_mac(mac_candidates, name_hint)

        return sys_name, sys_descr, serial, mac
    except Exception as e:
        log.warning("SNMP enrich failed for %s: %s", ip, e)
        return None, None, None, None


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
        # Called from zeroconf worker thread -> schedule onto main asyncio loop
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

        # For display only; qualification is handled by subnet scan
        print_ports = [mdns_port] if (mdns_port in QUALIFY_PORTS) else None
        web = await _pick_web_url(ip)

        hint = _extract_mdns_mac_hint(display)
        sys_name, sys_descr, serial, mac = await snmp_enrich(ip, hint)

        p = Printer(
            name=(sys_name or display),
            ip=ip,
            web=web,
            serial=serial,
            mac=mac,
            sys_descr=sys_descr,
            source="mdns",
            last_seen=_now(),
            print_ports=print_ports,
        )
        _merge_printer(p)


async def mdns_task():
    if not ENABLE_MDNS:
        return
    if MAIN_LOOP is None:
        return

    zc = Zeroconf(ip_version=IPVersion.V4Only)
    listener = MdnsListener(MAIN_LOOP)

    types = ["_printer._tcp.local.", "_ipp._tcp.local.", "_ipps._tcp.local."]
    _browsers = [ServiceBrowser(zc, t, listener) for t in types]

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        try:
            zc.close()
        except Exception:
            pass


# -------------------------
# Subnet scan + SNMP enrich
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
            sys_name, sys_descr, serial, mac = await snmp_enrich(ip, None)

            p = Printer(
                name=(sys_name or ip),
                ip=ip,
                web=web,
                serial=serial,
                mac=mac,
                sys_descr=sys_descr,
                source="scan",
                last_seen=_now(),
                print_ports=print_ports,
            )
            _merge_printer(p)

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
