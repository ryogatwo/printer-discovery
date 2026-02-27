import asyncio
import ipaddress
import os
import socket
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from fastapi import FastAPI
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf  # <-- key change

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

app = FastAPI(title="Printer Discovery", version="1.2.0")

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

# Only these ports qualify a device as a printer
QUALIFY_PORTS = [int(p) for p in os.getenv("QUALIFY_PORTS", "9100,631,515").split(",") if p.strip()]
# Only used to build a clickable link (do NOT qualify)
WEB_PORTS = [int(p) for p in os.getenv("WEB_PORTS", "443,80").split(",") if p.strip()]

# OIDs (best-effort)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_PRT_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"
OID_ENT_SERIAL_1 = "1.3.6.1.2.1.47.1.1.1.1.11.1"
OID_IF_PHYS_ADDR_BASE = "1.3.6.1.2.1.2.2.1.6"

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
    return ":".join(f"{b:02X}" for b in raw)


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


async def snmp_get(ip: str, oids: List[str]) -> Dict[str, str]:
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
        for vb in outVarBinds:
            out[vb[0].prettyPrint()] = vb[1].prettyPrint()
        return out
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


async def snmp_walk_first_mac(ip: str) -> Optional[str]:
    if not ENABLE_SNMP:
        return None

    snmpEngine = SnmpEngine()
    auth = CommunityData(SNMP_COMMUNITY, mpModel=1)  # v2c
    target = await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=SNMP_TIMEOUT,
        retries=SNMP_RETRIES,
    )
    ctx = ContextData()

    base = ObjectType(ObjectIdentity(OID_IF_PHYS_ADDR_BASE))

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
                return None

            for vb in varBinds:
                try:
                    raw = bytes(vb[1])
                except Exception:
                    raw = b""
                mac = _format_mac(raw)
                if mac:
                    return mac
        return None
    finally:
        try:
            snmpEngine.close_dispatcher()
        except Exception:
            pass


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
# mDNS discovery (AsyncZeroconf)
# -------------------------
class MdnsListener:
    def __init__(self, aiozc: AsyncZeroconf):
        self.aiozc = aiozc

    def add_service(self, zc, type_: str, name: str) -> None:
        asyncio.create_task(self._handle(type_, name))

    def update_service(self, zc, type_: str, name: str) -> None:
        asyncio.create_task(self._handle(type_, name))

    def remove_service(self, zc, type_: str, name: str) -> None:
        pass

    async def _handle(self, type_: str, name: str) -> None:
        # Use AsyncZeroconf helper (timeout is ms)
        info = await self.aiozc.async_get_service_info(type_, name, timeout=1500)
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

        p = Printer(
            name=display,
            ip=ip,
            web=web,
            source="mdns",
            last_seen=_now(),
            print_ports=print_ports,
        )
        _merge_printer(p)


async def mdns_task():
    if not ENABLE_MDNS:
        return

    aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
    listener = MdnsListener(aiozc)

    try:
        # These are the common printer-ish service types
        for t in ["_printer._tcp.local.", "_ipp._tcp.local.", "_ipps._tcp.local."]:
            await aiozc.async_add_service_listener(t, listener)

        while True:
            await asyncio.sleep(3600)
    finally:
        await aiozc.async_close()


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

            p = Printer(
                name=ip,
                ip=ip,
                web=web,
                source="scan",
                last_seen=_now(),
                print_ports=print_ports,
            )

            got = await snmp_get(ip, [OID_SYS_NAME, OID_SYS_DESCR, OID_PRT_SERIAL, OID_ENT_SERIAL_1])

            def pick_val(endswith: str) -> Optional[str]:
                for k, v in got.items():
                    if k.endswith(endswith):
                        return v
                return None

            sys_name = pick_val(OID_SYS_NAME)
            sys_descr = pick_val(OID_SYS_DESCR)
            serial = pick_val(OID_PRT_SERIAL) or pick_val(OID_ENT_SERIAL_1)

            if sys_name:
                p.name = sys_name
            if sys_descr:
                p.sys_descr = sys_descr
            if serial and serial.strip():
                p.serial = serial.strip()

            mac = await snmp_walk_first_mac(ip)
            if mac:
                p.mac = mac

            _merge_printer(p)

    tasks = [asyncio.create_task(scan_ip(str(h))) for h in net.hosts()]
    await asyncio.gather(*tasks)
    LAST_SCAN = _now()


async def scan_loop():
    while True:
        try:
            await scan_subnet_once()
        except Exception:
            pass
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
        "printers": [
            {
                **asdict(p),
                "details": p.details,
            }
            for p in items
        ],
    }


@app.on_event("startup")
async def startup():
    asyncio.create_task(scan_loop())
    asyncio.create_task(mdns_task())
