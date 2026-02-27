import asyncio
import ipaddress
import os
import socket
import time
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI
from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
    nextCmd,
)

app = FastAPI()

# ----------------------------
# Config (env)
# ----------------------------
SUBNETS = [s.strip() for s in os.getenv("SUBNETS", "10.1.10.0/24").split(",") if s.strip()]
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))  # seconds

PROBE_PORTS = [int(p) for p in os.getenv("PROBE_PORTS", "9100,631,80,443").split(",") if p.strip()]
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "0.35"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))

# Heuristic: if true, only count devices with 9100 or 631 as printers (reduces false positives)
REQUIRE_PRINT_PORT = os.getenv("REQUIRE_PRINT_PORT", "false").strip().lower() in ("1", "true", "yes", "y")

# Optional: reverse DNS is slow/noisy on some networks; default OFF
ENABLE_REVERSE_DNS = os.getenv("ENABLE_REVERSE_DNS", "false").strip().lower() in ("1", "true", "yes", "y")

# Optional: skip IPs
EXCLUDE_IPS = {x.strip() for x in os.getenv("EXCLUDE_IPS", "").split(",") if x.strip()}

# SNMP
ENABLE_SNMP = os.getenv("ENABLE_SNMP", "true").strip().lower() in ("1", "true", "yes", "y")
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
SNMP_TIMEOUT = float(os.getenv("SNMP_TIMEOUT", "0.6"))
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "0"))
SNMP_CONCURRENCY = int(os.getenv("SNMP_CONCURRENCY", "60"))

# Printer-MIB serial number: prtGeneralSerialNumber.1
OID_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"
# IF-MIB MAC addresses: ifPhysAddress.*
OID_IFPHYS = "1.3.6.1.2.1.2.2.1.6"

# mDNS service types to listen for
MDNS_TYPES = [
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
]

# ----------------------------
# Cache
# ----------------------------
_cache: Dict[str, object] = {"ts": 0.0, "data": []}


# ----------------------------
# Helpers
# ----------------------------
def _expand_subnets() -> List[str]:
    ips: List[str] = []
    for s in SUBNETS:
        net = ipaddress.ip_network(s, strict=False)
        for host in net.hosts():
            ip = str(host)
            if ip in EXCLUDE_IPS:
                continue
            ips.append(ip)
            # guardrail for giant nets
            if len(ips) > 4096:
                break
    return ips


async def _tcp_open(ip: str, port: int) -> bool:
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=TCP_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _probe_ip(ip: str, sem: asyncio.Semaphore) -> List[int]:
    async with sem:
        checks = await asyncio.gather(*[_tcp_open(ip, p) for p in PROBE_PORTS], return_exceptions=True)
        open_ports: List[int] = []
        for p, ok in zip(PROBE_PORTS, checks):
            if ok is True:
                open_ports.append(p)
        return open_ports


def _reverse_name(ip: str) -> Optional[str]:
    if not ENABLE_REVERSE_DNS:
        return None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def _best_url(ip: str, open_ports: List[int], mdns_port: Optional[int] = None) -> str:
    if 443 in open_ports:
        return f"https://{ip}"
    if 80 in open_ports:
        return f"http://{ip}"
    if mdns_port:
        return f"http://{ip}:{mdns_port}"
    if 631 in open_ports:
        return f"http://{ip}:631"
    return f"http://{ip}"


def _is_printer_candidate(open_ports: List[int], mdns_seen: bool) -> bool:
    if mdns_seen:
        return True
    if REQUIRE_PRINT_PORT:
        return (9100 in open_ports) or (631 in open_ports)
    return bool(set(open_ports) & {9100, 631, 80, 443})


def _fmt_mac(val) -> str:
    try:
        b = bytes(val)
        if not b or all(x == 0 for x in b):
            return ""
        if len(b) >= 6:
            b = b[-6:]
        return ":".join(f"{x:02x}" for x in b)
    except Exception:
        return ""


async def snmp_get(ip: str, oid: str) -> str:
    try:
        engine = SnmpEngine()
        target = UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
        community = CommunityData(SNMP_COMMUNITY, mpModel=1)  # SNMPv2c
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if errorIndication or errorStatus:
            return ""
        for _, val in varBinds:
            return str(val).strip()
        return ""
    except Exception:
        return ""


async def snmp_first_mac(ip: str) -> str:
    try:
        engine = SnmpEngine()
        target = UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
        community = CommunityData(SNMP_COMMUNITY, mpModel=1)  # SNMPv2c

        async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            engine, community, target, ContextData(),
            ObjectType(ObjectIdentity(OID_IFPHYS)),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                break
            for _, val in varBinds:
                mac = _fmt_mac(val)
                if mac:
                    return mac
        return ""
    except Exception:
        return ""


def _build_details(ip: str, mac: str, serial: str) -> str:
    parts = [f"IP: {ip}"]
    if mac:
        parts.append(f"MAC: {mac}")
    if serial:
        parts.append(f"SN: {serial}")
    return " | ".join(parts)


class _MDNSListener(ServiceListener):
    def __init__(self):
        self.found: Dict[str, Dict[str, object]] = {}

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name, timeout=1500)
        if not info or not info.addresses:
            return
        ip = socket.inet_ntoa(info.addresses[0])
        if ip in EXCLUDE_IPS:
            return
        port = info.port
        display = name.split("._")[0]
        self.found[ip] = {"name": display, "ip": ip, "mdns_port": port, "source": "mdns"}

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


async def discover_printers() -> List[Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}

    # 1) mDNS
    listener = _MDNSListener()
    try:
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        _ = [ServiceBrowser(zc, t, listener) for t in MDNS_TYPES]
        await asyncio.sleep(2.5)
        zc.close()
    except Exception:
        pass

    for ip, item in listener.found.items():
        results[ip] = item

    # 2) TCP probe
    ips = _expand_subnets()
    sem = asyncio.Semaphore(CONCURRENCY)
    probed = await asyncio.gather(*[_probe_ip(ip, sem) for ip in ips], return_exceptions=True)

    for ip, open_ports in zip(ips, probed):
        if not isinstance(open_ports, list):
            continue

        mdns_seen = ip in results
        if not _is_printer_candidate(open_ports, mdns_seen):
            continue

        existing = results.get(ip, {})
        mdns_port = existing.get("mdns_port") if isinstance(existing, dict) else None

        if isinstance(existing, dict) and existing.get("name"):
            name = str(existing["name"])
        else:
            name = _reverse_name(ip) or f"Printer {ip}"

        url = _best_url(ip, open_ports, mdns_port if isinstance(mdns_port, int) else None)

        merged = {
            "name": name,
            "ip": ip,
            "url": url,
            "open_ports": open_ports,
            "source": existing.get("source", "probe") if isinstance(existing, dict) else "probe",
        }
        if isinstance(mdns_port, int):
            merged["mdns_port"] = mdns_port

        results[ip] = merged

    # 3) SNMP enrich
    if ENABLE_SNMP and results:
        snmp_sem = asyncio.Semaphore(SNMP_CONCURRENCY)

        async def enrich_one(ip: str):
            async with snmp_sem:
                serial = await snmp_get(ip, OID_SERIAL)
                mac = await snmp_first_mac(ip)
                results[ip]["serial"] = serial or ""
                results[ip]["mac"] = mac or ""
                results[ip]["details"] = _build_details(ip, mac, serial)

        await asyncio.gather(*[enrich_one(ip) for ip in list(results.keys())], return_exceptions=True)
    else:
        for ip in results.keys():
            results[ip]["serial"] = ""
            results[ip]["mac"] = ""
            results[ip]["details"] = _build_details(ip, "", "")

    def ip_key(x: str) -> Tuple[int, int, int, int]:
        return tuple(int(p) for p in x.split("."))  # type: ignore

    return [results[k] for k in sorted(results.keys(), key=ip_key)]


async def _refresh_loop():
    while True:
        try:
            data = await discover_printers()
            _cache["data"] = data
            _cache["ts"] = time.time()
        except Exception:
            pass
        await asyncio.sleep(SCAN_INTERVAL)


@app.on_event("startup")
async def startup():
    asyncio.create_task(_refresh_loop())


@app.get("/api/printers")
def api_printers():
    return {"data": _cache["data"], "lastUpdated": _cache["ts"]}
