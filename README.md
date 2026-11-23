# getarp-intel — PoC

Cheap, easy-to-install defence intelligence: honeypot **sensors** catch attackers,
a **core** collects what they see, enriches it, scores it and shows it on a
dashboard.

This is the native proof-of-concept build:

- **Ubuntu 24.04 LTS**, on **amd64 or arm64** (Intel/AMD, or ARM such as AWS Graviton)
- **No containers.** Plain packages and systemd services, one installer
- **One core, any number of sensors.** Add a sensor at any time with two commands
- Not hardened to military grade. Sensible defaults: default-deny firewalls,
  one account per service, secrets generated on the machine, admin access only
  through a WireGuard tunnel

```
  attackers ──► sensor s01 ─┐                       ┌─► https://getarp.net         (public, read-only)
  attackers ──► sensor s02 ─┼─ WireGuard ─► core ───┤
  attackers ──► sensor sNN ─┘   (logs, one way)     └─► https://admin.getarp.internal (tunnel only)
```

## Quick start

You need two Ubuntu 24.04 machines with public IPv4 addresses, and a DNS name
for the dashboard pointing at the core.

**1. Core** (2 vCPU, 4 GB RAM, 30 GB disk is plenty for a PoC)

```bash
git clone https://github.com/cyberonit/getarp-intel.git && cd getarp-intel
sudo ./install.sh core --domain getarp.net --email you@example.com
```

It prints the first admin password. Then:

```bash
sudo getarp-ctl info        # prints the exact command for step 2, incl. the next free tunnel address
```

**2. Sensor** (1–2 vCPU, 2 GB RAM). Run the line `getarp-ctl info` printed, e.g.:

```bash
git clone https://github.com/cyberonit/getarp-intel.git && cd getarp-intel
sudo ./install.sh sensor --core <core-ip> --core-key <core-key> --tunnel-ip <tunnel-address>
```

It ends with one `getarp-ctl sensor add ...` line. **Run that line on the core.**
Within a minute `sudo getarp-ctl status` on the core shows the sensor and its events.

> After the sensor install, the machine's real SSH moves to another port (the installer
> prints it). The standard SSH port becomes the decoy.

**3. Your laptop** (to reach the admin site): see
[the user guide](docs/USER_GUIDE.md#4-connect-your-laptop-admin-access).

Each install ends by listing the ports to open in your cloud firewall / security
group for that machine. On a sensor, open the real SSH port to your own IP only.

## What runs where

| Core | Sensor |
|---|---|
| `getarp-ingest`: receives sensor logs through the tunnel | `getarp-cowrie`: SSH/Telnet decoy (Cowrie 3.1.7) |
| `getarp@pipeline`: normalises events into the database | `getarp-decoys`: HTTP, MySQL, FTP and Redis decoys |
| `getarp@enrichment`: threat-intel lookups | `getarp-suricata`: IDS (Suricata 7, ET Open rules) |
| `getarp@analytics`: scans, attacks, behaviour, 5-minute status | `getarp-shipper`: sends the logs to the core |
| `getarp@api` + Caddy: dashboard and admin site | `getarp-firewall`: default-deny in and out |
| PostgreSQL 17 + TimescaleDB, Redis, CrowdSec | WireGuard tunnel to the core |

## Day to day

```bash
sudo getarp-ctl status                 # services, tunnel, sensors, last event
sudo getarp-ctl sensor add s02 <tunnel-address> <key> <public-ip>
sudo getarp-ctl sensor remove s02      # revoke now; data is kept, the name/address is never reused
sudo getarp-ctl admin add laptop1 <tunnel-address> <key>
sudo getarp-ctl backup                 # also runs every night
```

## Repository layout

```
install.sh              one installer: "core" or "sensor"
bin/getarp-ctl          day-to-day operations (installed to /usr/local/sbin)
app/                    the application: pipeline, enrichment, analytics, API, frontend, db schema
core/                   ingest service, units and configs for the core
sensor/                 shipper, decoys, Cowrie/Suricata configs and units for a sensor
common/                 the firewall unit used by both roles
tests/                  render-test.sh (firewall/tunnel/registry), ship-test.sh (sensor -> core delivery)
docs/USER_GUIDE.md      install, connect, operate, troubleshoot
```

## Documentation

- **[User guide](docs/USER_GUIDE.md)**: everything above in detail, plus troubleshooting and the PoC's limits.

## Licence and third-party software

getarp's own code is in this repository. Cowrie, Suricata, CrowdSec, PostgreSQL,
TimescaleDB, Redis, Caddy and WireGuard are installed from their own projects
under their own licences.
