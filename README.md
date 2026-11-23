# getarp-intel — PoC

Cheap, easy-to-install defence intelligence: honeypot **sensors** catch attackers,
a **core** collects what they see, scores it and shows it on a live dashboard.

This is the native proof-of-concept build:

- **Ubuntu 24.04 LTS**, on **amd64 or arm64** (Intel/AMD, or ARM such as AWS Graviton)
- **No containers.** Plain packages and systemd services, one installer
- **One core, any number of sensors.** Add a sensor at any time with two commands
- Not hardened to military grade. Sensible defaults: default-deny firewalls,
  one account per service, secrets generated on the machine, a key per sensor,
  admin features only from addresses you allow

```
  attackers ──► sensor s01 ─┐                        ┌─► https://getarp.net   (public, read-only)
  attackers ──► sensor s02 ─┼── HTTPS, one way ─► core
  attackers ──► sensor sNN ─┘   (logs + sensor key)  └─► same site, from admin addresses: sign-in, IP detail
```

## Quick start

You need Ubuntu 24.04 machines with public IPv4 addresses, and a DNS name for
the dashboard pointing at the core.

**1. Core** (2 vCPU, 4 GB RAM, 30 GB disk is plenty for a PoC). Run it from the
computer you will administer from: that address is allowed admin access.

```bash
git clone https://github.com/cyberonit/getarp-intel.git && cd getarp-intel
sudo ./install.sh core --domain getarp.net --email you@example.com
```

It prints the first admin password.

**2. Register a sensor on the core.** It prints the sensor's key and the exact
install command:

```bash
sudo getarp-ctl sensor add s01 <sensor-public-ip>
```

**3. Sensor** (1–2 vCPU, 2 GB RAM). Run the command step 2 printed:

```bash
git clone https://github.com/cyberonit/getarp-intel.git && cd getarp-intel
sudo ./install.sh sensor --core https://getarp.net --key <key>
```

Within a minute of the first scanner finding it, the sensor's events are on the
dashboard (`sudo getarp-ctl status` on the core shows them arriving).

> After the sensor install, the machine's real SSH moves to another port (the
> installer prints it). The standard SSH port becomes the decoy.

Each install ends by listing the ports to open in your cloud firewall / security
group for that machine.

## What runs where

| Core | Sensor |
|---|---|
| Caddy: HTTPS for the dashboard and for sensor deliveries | `getarp-cowrie`: SSH/Telnet decoy (Cowrie 3.1.7) |
| `getarp-ingest`: checks each delivery's key, stores the logs | `getarp-decoys`: HTTP, MySQL, FTP and Redis decoys |
| `getarp@pipeline`: events, scans, attacks, scores, live status | `getarp-suricata`: IDS (Suricata 7, ET Open rules) |
| `getarp@enrichment`: optional threat-intel reputation | `getarp-shipper`: sends the logs to the core over HTTPS |
| `getarp@api`: the dashboard's data and sign-in | `getarp-firewall`: default-deny in and out |
| PostgreSQL 17 + TimescaleDB, CrowdSec | |

Country and network data come from the free DB-IP Lite databases (offline, no
account). Threat-intel reputation (CrowdSec CTI or AbuseIPDB) is optional.

## Day to day

```bash
sudo getarp-ctl status                     # services, sensors, last event
sudo getarp-ctl sensor add s02 <public-ip> # register another sensor
sudo getarp-ctl sensor remove s02          # revoke now; data is kept, the name is never reused
sudo getarp-ctl admin add office <ip>      # allow admin sign-in from another address
sudo getarp-ctl password admin             # set a dashboard password
sudo getarp-ctl backup                     # also runs every night
```

## Repository layout

```
install.sh              one installer: "core" or "sensor"
bin/getarp-ctl          day-to-day operations (installed to /usr/local/sbin)
bin/getarp-geoip        monthly download of the DB-IP Lite country/network data
app/getarp/             the application: pipeline, enrichment, API (Python)
app/migrations/         database schema, applied in order by the installer
app/frontend/           the dashboard (React)
app/tests/              unit tests and an end-to-end test against PostgreSQL
core/                   ingest service, units and configs for the core
sensor/                 shipper, decoys, Cowrie/Suricata configs and units for a sensor
common/                 the firewall unit used by both roles
tests/                  render-test.sh (firewall, web server, registry), ship-test.sh (delivery)
docs/USER_GUIDE.md      install, operate, troubleshoot
```

## Documentation

- **[User guide](docs/USER_GUIDE.md)**: everything above in detail, plus troubleshooting and the PoC's limits.

## Licence and third-party software

getarp's own code is in this repository. Cowrie, Suricata, CrowdSec, PostgreSQL,
TimescaleDB and Caddy are installed from their own projects under their own
licences. IP data by [DB-IP](https://db-ip.com) (CC BY 4.0).
