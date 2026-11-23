# getarp PoC — user guide

This guide takes you from empty Ubuntu machines to a working getarp with one
sensor, then shows how to add more sensors, sign in as an admin, run it day to
day and fix the usual problems.

Contents

1. [How it fits together](#1-how-it-fits-together)
2. [Install the core](#2-install-the-core)
3. [Add a sensor](#3-add-a-sensor)
4. [Admin access](#4-admin-access)
5. [Check that it works](#5-check-that-it-works)
6. [Add or remove sensors](#6-add-or-remove-sensors)
7. [Day-to-day operations](#7-day-to-day-operations)
8. [Where things are](#8-where-things-are)
9. [Troubleshooting](#9-troubleshooting)
10. [Limits of this PoC](#10-limits-of-this-poc)

---

## 1. How it fits together

```
                       internet
   attackers ──────────────┬─────────────────────────────┐
                           ▼                             ▼
             ┌──────── sensor s01 ────────┐      ┌──────────────── core ─────────────────┐
             │ decoys: SSH/Telnet (Cowrie)│      │ Caddy (HTTPS)                         │
             │   HTTP, MySQL, FTP, Redis  │      │  ├─ /ingest ◄── registered sensors    │
             │ Suricata IDS               │HTTPS │  │    getarp-ingest checks the key    │
             │ shipper ───────────────────┼─────►│  │    pipeline → PostgreSQL           │
             │ firewall: deny in and out  │ one  │  ├─ dashboard, read-only ◄── everyone │
             └────────────────────────────┘ way  │  └─ sign-in, IP detail ◄── admin IPs  │
                                                 │ CrowdSec bans attackers               │
                                                 └───────────────────────────────────────┘
```

- **Sensors** look like weak servers. Everything attackers do there is logged.
- Each sensor **pushes** its logs to the core over HTTPS, with its own secret
  key. The core never connects to a sensor.
- The core accepts a delivery only from a **registered sensor address** and
  with a **valid key**. It knows which sensor sent it from the key, never from
  what the sensor says about itself. A removed sensor is cut off at once.
- The **dashboard** is public and read-only. **Signing in** and **per-IP
  detail** work only from the admin addresses you allow, and need a password.

## 2. Install the core

**Machine:** Ubuntu 24.04 LTS, amd64 or arm64, 2 vCPU, 4 GB RAM, 30 GB disk,
a public IPv4 address. On AWS a `t4g.medium` (ARM) or `t3.medium` is fine.

**Before you start**

1. Point the dashboard's DNS name at the core: `getarp.net  A  <core public IP>`.
   The HTTPS certificate is requested on first start and needs this.
2. In the cloud firewall / security group, open the web ports and your SSH
   port. The installer lists them at the end; you can also open them right
   after it finishes.

**Install** (from the computer you will administer from: its address becomes
the first admin address)

```bash
git clone https://github.com/cyberonit/getarp-intel.git
cd getarp-intel
sudo ./install.sh core --domain getarp.net --email you@example.com
```

It takes about 5–10 minutes. Options you may want:

| Option | Default | Meaning |
|---|---|---|
| `--admin-user NAME` | `admin` | first dashboard login |
| `--admin-cidr LIST` | the address you are connected from | admin addresses (single IPs or ranges, comma separated) |
| `--ssh-port N` | detected | SSH port(s) the firewall keeps open, comma separated |
| `--public-ip IP` / `--bind-ip IP` | detected | only if detection gets it wrong |
| `--backup-s3 s3://bucket/prefix` | none | also copy nightly backups to S3 (needs an instance role or AWS credentials allowed to `PutObject`) |

The installer:

- adds the PostgreSQL, TimescaleDB and CrowdSec package sources and installs everything
- makes one system account per service, and random passwords for the database
  (kept in `/etc/getarp/secrets.env`, root only)
- turns on the firewall (it keeps your SSH port and your current session open)
- creates the database, downloads the country/network data, builds the
  dashboard, configures Caddy and CrowdSec
- prints the **first admin password** (also kept in `/etc/getarp/admin-password`)

You can run it again at any time (for example after `git pull`). Keys,
passwords, the registry and the data are kept.

Change the admin password after your first sign-in:

```bash
sudo getarp-ctl password admin
```

## 3. Add a sensor

**Machine:** Ubuntu 24.04 LTS, amd64 or arm64, 1–2 vCPU, **2 GB RAM** (Suricata
needs it), 20 GB disk, a public IPv4 address that does not change. A **fresh,
dedicated machine**: it will be attacked all day.

**1. Register it on the core** with a name and its public address:

```bash
sudo getarp-ctl sensor add s01 <sensor-public-ip>
```

It prints the sensor's **key** (shown only once; the core keeps just a hash of
it) and the exact install command.

**2. Install it on the sensor machine** with that command:

```bash
git clone https://github.com/cyberonit/getarp-intel.git
cd getarp-intel
sudo ./install.sh sensor --core https://getarp.net --key <key>
```

Before changing anything, the installer sends an empty test delivery. If the
core refuses it, the installer stops and says why (unknown key, or a different
public address than the one registered).

| Option | Default | Meaning |
|---|---|---|
| `--admin-cidr LIST` | the address you are connected from | who may reach the sensor's real SSH from the internet |
| `--iface NAME` | detected | the public network interface |
| `--public-ip IP` | detected | only if detection gets it wrong |

What changes on the sensor:

- **Real SSH moves to another port** (the installer prints it; below it is
  `<ssh-port>`). The standard SSH port now goes to the Cowrie decoy. Your
  current session stays open; new logins use `ssh -p <ssh-port> ...`, from the
  admin addresses only.
- A default-deny firewall in **and out**. The decoy accounts cannot open any
  connection at all; only the shipper may talk to the core, and only over
  HTTPS; only system accounts may reach the internet (updates, DNS, time).
- Cowrie, the extra decoys, Suricata and the shipper start.

**3. Open the sensor's ports** in its cloud firewall / security group as the
installer lists them: the decoy ports to the internet, the real SSH port to
your own address only.

Within a minute of the first scanner finding the sensor (usually minutes),
`sudo getarp-ctl status` on the core shows its **LAST-EVENT** moving.

## 4. Admin access

There is one site. From anywhere it shows the read-only dashboard. From an
**admin address** the menu also shows **Sign in**; once signed in, clicking an
IP opens its full detail (logins tried, commands typed, every event).

```bash
sudo getarp-ctl admin add office <ip-or-range>   # allow another address
sudo getarp-ctl admin remove office
sudo getarp-ctl list                             # sensors and admin addresses
sudo getarp-ctl password <user>                  # add a login or change its password
```

Your admin addresses are also never banned by CrowdSec. If you work from a
changing address, add the range your provider uses, or add the new address
from the cloud console when it changes.

## 5. Check that it works

From a machine that is **not** an admin address:

| Test | Expected |
|---|---|
| `ssh root@<sensor IP>` | a login prompt from the decoy; the attempt shows on the dashboard within a minute |
| `curl http://<sensor IP>/` | a fake "Admin Portal" page |
| `ssh -p <ssh-port> <sensor IP>` | times out |
| `curl https://getarp.net/api/status` | JSON, HTTP 200 |
| `curl -i https://getarp.net/api/me` | HTTP 404 (admin routes are hidden) |
| `curl -i https://getarp.net/api/ips/<any IP>` | HTTP 404 |
| `curl -i -X POST https://getarp.net/ingest` | HTTP 404 (not a registered sensor) |

From an admin address: `curl -i https://getarp.net/api/me` answers 401 (exists,
but needs a sign-in).

On the sensor:

```bash
sudo -u cowrie curl -m5 https://example.com      # fails: decoys have no way out
sudo -u getarp-ship curl -m5 https://example.com # fails: the shipper only reaches the core
sudo getarp-ctl status                           # all services active, latest delivery
```

On the core:

```bash
sudo getarp-ctl status
sudo tail -f /var/lib/getarp/logs/cowrie.json    # records arriving, each with "getarp_sensor"
sudo cscli decisions list                        # attackers CrowdSec has banned
```

## 6. Add or remove sensors

Repeat [section 3](#3-add-a-sensor) for each new sensor, with a new name. Its
events go to the same dashboard, tagged with its name.

| Task | Command (on the core) |
|---|---|
| Sensor's public address changed | `sudo getarp-ctl sensor move s02 <new-ip>` |
| Remove a sensor (retired or compromised) | `sudo getarp-ctl sensor remove s02` |

Removing takes effect at once: its key and its address stop working. Its
collected data stays. Its name is never handed out again, so give a rebuilt
sensor a new name (and a new key, which `sensor add` makes).

## 7. Day-to-day operations

| Task | Command (on the core unless noted) |
|---|---|
| Everything at a glance | `sudo getarp-ctl status` (also on a sensor) |
| What this machine is | `sudo getarp-ctl info` (also on a sensor) |
| Rebuild firewall and web server config from the registry | `sudo getarp-ctl apply` |
| Backup now | `sudo getarp-ctl backup` (runs nightly; 7 days kept in `/var/backups/getarp`) |
| Restore a backup | see [Restoring a backup](#restoring-a-backup) below |
| Service logs | `journalctl -u getarp@pipeline -f` (or `getarp-ingest`, `getarp@api`, `getarp-cowrie`, ...) |
| Restart the application | `sudo systemctl restart 'getarp@*'` |
| Update getarp | `cd getarp-intel && git pull && sudo ./install.sh core ...` with the same options (on sensors: `... sensor --core ... --key ...`) |
| Threat-intel reputation | put `CROWDSEC_CTI_KEY=...` or `ABUSEIPDB_KEY=...` under "your settings" in `/etc/getarp/svc/enrichment.env`, then `sudo systemctl restart getarp@enrichment` |
| Detection thresholds | `/etc/getarp/app.env`, then `sudo systemctl restart getarp@pipeline` |
| Country/network data now | `sudo getarp-geoip` (runs monthly by itself) |
| Banned attackers | `sudo cscli decisions list`; unban: `sudo cscli decisions delete --ip <ip>` |

### Restoring a backup

```bash
sudo systemctl stop 'getarp@*' getarp-ingest
sudo -u postgres psql -c "DROP DATABASE getarp" -c "CREATE DATABASE getarp"
sudo -u postgres psql -d getarp -c "CREATE EXTENSION timescaledb" -c "SELECT timescaledb_pre_restore()"
sudo -u postgres pg_restore -d getarp < /var/backups/getarp/getarp-<time>.dump
sudo -u postgres psql -d getarp -c "SELECT timescaledb_post_restore()"
cd getarp-intel && sudo ./install.sh core ...   # same options as before: restores the service logins
```

Operating-system security updates install automatically (Ubuntu's
unattended-upgrades). Suricata's rules refresh daily on each sensor.

## 8. Where things are

**Core**

| Path | What |
|---|---|
| `/etc/getarp/core.env` | settings written by the installer |
| `/etc/getarp/peers.csv` | the registry: sensors (name, key hash, address) and admin addresses |
| `/etc/getarp/secrets.env` | database passwords, session secret (root only) |
| `/etc/getarp/app.env`, `/etc/getarp/svc/*.env` | application settings, per-service logins |
| `/etc/getarp/nftables.nft` | firewall rules (generated) |
| `/etc/caddy/Caddyfile` | web server (generated by `getarp-ctl`) |
| `/var/lib/getarp/logs/` | sensor logs as received (`cowrie.json`, `eve.json`, `extra.json`), 7 days |
| `/var/lib/getarp/ingest/status.json` | per-sensor delivery counters |
| `/var/lib/getarp/geoip/` | DB-IP Lite country/network data |
| `/var/backups/getarp/` | nightly database dumps |
| `/opt/getarp/` | application code and its Python environment |
| `/var/www/getarp/` | the built dashboard |

**Sensor**

| Path | What |
|---|---|
| `/etc/getarp/sensor.env` | settings written by the installer |
| `/etc/getarp/shipper.env` | the core's address and this sensor's key (root and the shipper only) |
| `/etc/cowrie/` | Cowrie settings and the accepted decoy logins (`userdb.txt`) |
| `/etc/getarp/suricata.yaml`, `/etc/getarp/getarp-local.rules` | Suricata settings and getarp's own rules |
| `/var/log/getarp/{cowrie,extra,suricata}/` | the decoy and IDS logs (the buffer while the core is away) |
| `/var/lib/getarp-shipper/state.json` | how far the shipper has delivered |

## 9. Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| Sensor shows `LAST-EVENT never` | `journalctl -u getarp-shipper -n 50` on the sensor | "core answered 401": the key is unknown or was removed. "core answered 404": the sensor's public address is not the registered one (`getarp-ctl sensor move`). Connection errors: DNS, certificate or the core's web port. Otherwise nobody has attacked yet: try `ssh root@<sensor IP>` from outside. |
| Events in `/var/lib/getarp/logs` but not on the dashboard | `journalctl -u getarp@pipeline -n 50` | Database login errors: re-run the installer, it rewrites the logins. |
| `https://getarp.net` has no certificate | `journalctl -u caddy -n 50` | DNS must point at the core and the web ports must be open. Caddy retries by itself. |
| No "Sign in" in the menu | `sudo getarp-ctl list` | Your current address is not an admin address: `sudo getarp-ctl admin add <name> <your ip>` (from the cloud console if needed). |
| Locked out of a sensor's SSH | cloud console | Edit `ADMIN_CIDR` in `/etc/getarp/sensor.env`, then `sudo getarp-ctl apply`. |
| Locked out of the core's SSH | cloud console | `sudo nft delete table inet getarp` opens the firewall until the next boot; re-run the installer with `--ssh-port`. |
| Your own IP got banned | `sudo cscli decisions list` on the core | `sudo cscli decisions delete --ip <your ip>`, and add it as an admin address so it is never banned again. |
| Suricata keeps restarting | `journalctl -u getarp-suricata -n 50` | Usually memory: give the sensor 2 GB or more. |
| No countries or networks on the dashboard | `ls /var/lib/getarp/geoip` | `sudo getarp-geoip` (needs outbound HTTPS from the core). |
| Disk filling up | `sudo getarp-ctl status` (Disk) | Raw events are kept 90 days (compressed after 7), findings 180 days, log files 7 days. Remove old dumps in `/var/backups/getarp`. |

Install logs are in `/var/log/getarp-install.log` on each machine.

## 10. Limits of this PoC

This is a proof of concept, built to be cheap and easy to run. Known limits,
accepted on purpose:

- **One core, one database.** No high availability. Backups are local (7 days)
  unless you give `--backup-s3`. Test a restore before relying on it.
- **The dashboard is public.** Attacker addresses, scores, countries, networks,
  scans, attacks and behaviour summaries are visible to anyone. Per-IP detail
  (passwords tried, commands typed) is admin-only.
- **Admin access is by address plus password.** There is no second factor;
  keep the admin address list short.
- **Sensors need a fixed public address**, because the core only accepts
  deliveries from registered addresses. A sensor behind a changing address needs
  `getarp-ctl sensor move` after each change.
- **Delivery from sensor to core** survives restarts and outages on either
  side (the sensor's log files are the buffer) and loses nothing; a batch the
  core did not confirm is sent again. A sensor sending very fast is slowed
  down, not cut off.
- **CrowdSec bans** attackers on the core only (they lose the dashboard), not on
  the sensors: sensors must keep seeing attackers.
- **Cowrie is pinned** to 3.1.7; upgrading it is a deliberate change to
  `install.sh`.
- Not included in this version: reports, docs and contact pages, email
  alerting, multiple admin roles, importing data from the earlier build.
