Printer Discovery (mDNS + SNMP) for Homepage / Portainer
========================================================

This project runs a small FastAPI service that:
- Discovers network printers via mDNS (_ipp, _ipps, _printer)
- Optionally enriches results via SNMP (MAC, serial, etc. best-effort)
- Exposes a JSON API that Homepage can consume via the Custom API widget

API Endpoints
-------------
- GET /health
- GET /api/printers

Example /health response:
  {
    "ok": true,
    "subnet": "10.1.10.0/24",
    "qualify_ports": [9100, 631, 515],
    "web_ports": [443, 80],
    "enable_mdns": true,
    "enable_snmp": true
  }

Example /api/printers response includes:
- count
- printers[] with fields: name, ip, web, serial, mac, sys_descr, source, last_seen, print_ports, details


------------------------------------------------------------
Portainer (Community Edition) Deployment
------------------------------------------------------------

IMPORTANT NOTES
1) For best mDNS results you generally want host networking:
   - network_mode: host
   - (No ports: mapping is needed; host mode exposes the container port directly on the host)
   Host networking is a standard Docker Compose option. (See Docker Compose networking docs.) :contentReference[oaicite:1]{index=1}

2) If you cannot use host networking (or you’re deploying to Swarm),
   you can run in bridge mode but should set ENABLE_MDNS=false and rely
   on subnet scan only (or accept that mDNS may not work reliably).

3) SNMP enrichment depends on printers having SNMP enabled and the community string matching.
   If printers don’t respond to SNMP, MAC/Serial may show as null.

------------------------------------------------------------
Option A (Recommended): Portainer Stack (host network, mDNS ON)
------------------------------------------------------------

Portainer UI steps:
1) Stacks -> Add stack
2) Name: printer-discovery
3) Paste the docker-compose below
4) Deploy the stack
5) For updates: Stacks -> printer-discovery -> Update stack -> (enable "Re-pull image") -> Update

docker-compose.yml (host network):
---------------------------------
version: "3.8"
services:
  printer-discovery:
    image: ghcr.io/ryogatwo/printer-discovery:latest
    restart: unless-stopped
    network_mode: host
    environment:
      - SUBNET=10.1.10.0/24
      - PORT=8787

      - SCAN_INTERVAL=120
      - CONNECT_TIMEOUT=0.25
      - CONCURRENCY=200

      # Only these qualify a device as a printer (helps avoid “web things”)
      - QUALIFY_PORTS=9100,631,515
      # Only used to build clickable web links
      - WEB_PORTS=443,80

      - ENABLE_MDNS=true
      - ENABLE_SNMP=true

      - SNMP_COMMUNITY=public
      - SNMP_PORT=161
      - SNMP_TIMEOUT=1.0
      - SNMP_RETRIES=0

Testing:
- http://<HOST-IP>:8787/health
- http://<HOST-IP>:8787/api/printers


------------------------------------------------------------
Option B: Portainer Stack (bridge network, mDNS OFF, port mapping ON)
------------------------------------------------------------

Use this if host networking is not available/desired.

version: "3.8"
services:
  printer-discovery:
    image: ghcr.io/ryogatwo/printer-discovery:latest
    restart: unless-stopped
    ports:
      - "8787:8787"
    environment:
      - SUBNET=10.1.10.0/24
      - PORT=8787

      - SCAN_INTERVAL=120
      - CONNECT_TIMEOUT=0.25
      - CONCURRENCY=200

      - QUALIFY_PORTS=9100,631,515
      - WEB_PORTS=443,80

      - ENABLE_MDNS=false
      - ENABLE_SNMP=true

      - SNMP_COMMUNITY=public
      - SNMP_PORT=161
      - SNMP_TIMEOUT=1.0
      - SNMP_RETRIES=0

Testing:
- http://<HOST-IP>:8787/health
- http://<HOST-IP>:8787/api/printers


------------------------------------------------------------
Portainer Custom Template (CE) - How to add it
------------------------------------------------------------

Portainer docs: Templates -> Custom templates. :contentReference[oaicite:2]{index=2}

Portainer UI steps:
1) Templates -> Custom -> Add Custom Template
2) Title: Printer Discovery
3) Platform: Linux
4) Type: Standalone / Podman (NOT Swarm)
5) Method: Web editor
6) Paste ONE of the compose files above (Option A or B)
7) Create custom template
8) Deploy from the template and adjust environment values if needed


------------------------------------------------------------
Homepage Integration (Custom API widget)
------------------------------------------------------------

Homepage supports a Custom API widget that can map fields from your JSON response.
Docs for `customapi`, mappings, and `dynamic-list` are here: :contentReference[oaicite:3]{index=3}

Where to put this:
- In Homepage, edit your services.yaml and add one (or both) of the examples below.

IMPORTANT:
- If Homepage runs in Docker and printer-discovery runs in host network mode,
  Homepage should access it via the Docker host’s IP/hostname (e.g. http://10.1.10.5:8787),
  not the container name (because host-network containers are not on the same Docker bridge network).

------------------------------------------------------------
Homepage Example 1: Summary Card (count + last_scan)
------------------------------------------------------------

services.yaml snippet:

- Infrastructure:
    - Printer Discovery:
        href: http://10.1.10.5:8787/health
        description: mDNS + SNMP printer discovery API
        widget:
          type: customapi
          url: http://10.1.10.5:8787/api/printers
          refreshInterval: 30000
          mappings:
            - field: count
              label: Printers
              format: number
            - field: last_scan
              label: Last Scan (epoch)
              format: text
            - field: subnet
              label: Subnet
              format: text

(Homepage supports many formats + transformations; see docs.) :contentReference[oaicite:4]{index=4}


------------------------------------------------------------
Homepage Example 2: Dynamic List (printer name on left, IP on right, clickable)
------------------------------------------------------------

This displays each discovered printer as a row.

services.yaml snippet:

- Infrastructure:
    - Network Printers:
        href: http://10.1.10.5:8787/api/printers
        widget:
          type: customapi
          url: http://10.1.10.5:8787/api/printers
          refreshInterval: 30000
          display: dynamic-list
          mappings:
            items: printers
            name: name
            label: ip
            # Makes rows clickable. Homepage supports templated targets using {field}
            # (Docs show {id} example; here we use {web} or {ip}). :contentReference[oaicite:5]{index=5}
            target: "{web}"
            limit: 25

Alternative (click web UI using IP only):
            target: "http://{ip}/"


------------------------------------------------------------
Troubleshooting
------------------------------------------------------------

- Homepage widget shows nothing:
  - Verify Homepage container can reach the API URL you configured.
  - The Homepage troubleshooting guide suggests testing connectivity from inside the container. :contentReference[oaicite:6]{index=6}

- SNMP fields are null:
  - Enable SNMP on the printer(s)
  - Confirm community string matches SNMP_COMMUNITY
  - Some devices don’t expose Printer-MIB serial OIDs; results vary by vendor.

- Too many/too few printers:
  - QUALIFY_PORTS controls what qualifies as a “printer”.
  - If you have non-printers with 515/631/9100 open, tighten QUALIFY_PORTS.
  - If you rely on mDNS, confirm ENABLE_MDNS=true and host networking is used.

Environment Variables
---------------------
SUBNET            CIDR to scan (default: 10.1.10.0/24)
PORT              API port (default: 8787)
SCAN_INTERVAL     Seconds between subnet scans
CONNECT_TIMEOUT   TCP probe timeout seconds
CONCURRENCY       Concurrent scan tasks

QUALIFY_PORTS     Ports that qualify a device as a printer (default: 9100,631,515)
WEB_PORTS         Ports to use for building web links (default: 443,80)

ENABLE_MDNS       true/false
ENABLE_SNMP       true/false
SNMP_COMMUNITY    SNMP v2c community string
SNMP_PORT         default 161
SNMP_TIMEOUT      seconds
SNMP_RETRIES      integer
