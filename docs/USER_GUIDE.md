# getarp PoC — user guide

This guide takes you from two empty Ubuntu machines to a working getarp with
one sensor, then shows how to add more sensors, reach the admin site, run it
day to day and fix the usual problems.

Contents

1. [How it fits together](#1-how-it-fits-together)
2. [Install the core](#2-install-the-core)
3. [Install a sensor](#3-install-a-sensor)
4. [Connect your laptop (admin access)](#4-connect-your-laptop-admin-access)
5. [Check that it works](#5-check-that-it-works)
6. [Add more sensors](#6-add-more-sensors)
7. [Day-to-day operations](#7-day-to-day-operations)
8. [Where things are](#8-where-things-are)
9. [Troubleshooting](#9-troubleshooting)
10. [Limits of this PoC](#10-limits-of-this-poc)

---

## 1. How it fits together

```
                      internet
   attackers ─────────────┬──────────────────────────────┐
                          ▼                              ▼
             ┌──────── sensor s01 ────────┐      ┌──────── core ─────────────────────┐
             │ decoys: SSH/Telnet (Cowrie)│      │ getarp-ingest  ◄── tunnel only    │
             │   HTTP, MySQL, FTP, Redis  │      │ pipeline → PostgreSQL+TimescaleDB │
             │ Suricata IDS               │ WG   │ enrichment (threat intel)         │
             │ shipper ───────────────────┼─────►│ analytics (scans, attacks, ...)   │
             │ firewall: deny in and out  │ one  │ API + Caddy ──► https://getarp.net│
             └────────────────────────────┘ way  │ CrowdSec bans attackers           │
                                                 │ admin site ◄── your laptop (WG)   │
                                                 └───────────────────────────────────┘
```

- **Sensors** look like weak servers. Everything attackers do there is logged.
- Each sensor has a **WireGuard tunnel** to the core and **pushes** its logs
  through it. The core never connects to a sensor.
- The core knows which sensor sent a record **from the tunnel address**, never
  from what the sensor says about itself. A revoked sensor is cut off at once.
- The **public dashboard** shows the live picture, read-only. Logging in,
  settings, per-IP detail and reports are only on the **admin site**, which is
  reachable only through the tunnel from your laptop.

Tunnel addresses come from one private range, with separate blocks for the
core, admin laptops and sensors. You never pick one by hand: `getarp-ctl info`
prints the next free address for a sensor or a laptop. Addresses and names are
never reused, not even after removal.

## 2. Install the core

**Machine:** Ubuntu 24.04 LTS, amd64 or arm64, 2 vCPU, 4 GB RAM, 30 GB disk,
a public IPv4 address. On AWS a `t4g.medium` (ARM) or `t3.medium` is fine.

**Before you start**

1. Point the dashboard's DNS name at the core: `getarp.net  A  <core public IP>`.
   The HTTPS certificate is requested on first start and needs this.
2. In the cloud firewall / security group, open the web ports, the tunnel port
   and your SSH port to the internet. The installer lists them at the end; if
   you are unsure, open them right after the install finishes.

**Install**

```bash
git clone https://github.com/cyberonit/getarp-intel.git
cd getarp-intel
sudo ./install.sh core --domain getarp.net --email you@example.com
```

It takes about 5–10 minutes. Options you may want:

| Option | Default | Meaning |
|---|---|---|
| `--admin-user NAME` | `admin` | first dashboard login |
| `--admin-domain NAME` | `admin.getarp.internal` | name of the tunnel-only admin site |
| `--ssh-port N` | detected | SSH port(s) the firewall keeps open, comma separated |
| `--public-ip IP` / `--bind-ip IP` | detected | only if detection gets it wrong |
| `--backup-s3 s3://bucket/prefix` | none | also copy nightly backups to S3 (needs an instance role or AWS credentials allowed to `PutObject`) |

The installer:

- adds the PostgreSQL, TimescaleDB and CrowdSec package sources and installs everything
- makes one system account per service, and random passwords for the database
  and Redis (kept in `/etc/getarp/secrets.env`, root only)
- creates the core's tunnel key and turns on the firewall (it keeps your SSH
  port and your current session open)
- creates the database, builds the dashboard, configures Caddy and CrowdSec
- prints the **first admin password** (also kept in `/etc/getarp/admin-password`)

You can run it again at any time (for example after `git pull`). Keys,
passwords, the registry and the data are kept.

Change the admin password when you first log in:

```bash
sudo getarp-ctl password admin
```

## 3. Install a sensor

**Machine:** Ubuntu 24.04 LTS, amd64 or arm64, 1–2 vCPU, **2 GB RAM** (Suricata
needs it), 20 GB disk, a public IPv4 address. A **fresh, dedicated machine**:
it will be attacked all day.

**Ports.** The sensor install ends by listing what to open in its cloud
firewall / security group: the decoy ports to the internet, and the machine's
new real SSH port **to your own IP only**.

**Get the command from the core**

```bash
# on the core
sudo getarp-ctl info
```

It prints the core's tunnel key, the next free sensor address and a complete
line like this one. Run it on the sensor:

```bash
git clone https://github.com/cyberonit/getarp-intel.git
cd getarp-intel
sudo ./install.sh sensor --core <core-ip> --core-key <core-key> --tunnel-ip <tunnel-address>
```

| Option | Default | Meaning |
|---|---|---|
| `--name NAME` | `s01`, `s02`, ... from the tunnel address | the sensor's name on the dashboard |
| `--admin-cidr CIDR` | the IP you are connected from | who may reach the real SSH port from the internet; `none` = only through the tunnel |
| `--iface NAME` | detected | the public network interface |
| `--public-ip IP` | detected | only if detection gets it wrong |

What changes on the sensor:

- **Real SSH moves to another port** (the installer prints it; below it is
  `<ssh-port>`). The standard SSH port now goes to the Cowrie decoy. Your
  current session stays open; new logins use `ssh -p <ssh-port> ...`.
- A default-deny firewall in **and out**. The decoy accounts cannot open any
  connection at all; only the shipper may talk to the core; only system
  accounts may reach the internet (updates, DNS, time).
- Cowrie, the extra decoys, Suricata and the shipper start.

**Register the sensor on the core.** The sensor install ends with one line.
Copy it and run it **on the core**:

```bash
sudo getarp-ctl sensor add s01 <tunnel-address> <sensor-key> <sensor-public-ip>
```

Within a minute, `sudo getarp-ctl status` on the sensor shows a recent
handshake, and on the core the sensor's **LAST-EVENT** column starts moving
(scanners find a new machine in minutes).

## 4. Connect your laptop (admin access)

The admin site and the sensors' SSH are reachable only through the tunnel.

1. **Install WireGuard** on the laptop (wireguard.com/install). In the app,
   choose *Add empty tunnel*: it creates a key pair. Copy the **public** key.
   (Command line: `wg genkey | tee laptop.key | wg pubkey`.)
2. **Register the laptop on the core:**

   ```bash
   sudo getarp-ctl info        # shows the next free laptop address
   sudo getarp-ctl admin add laptop1 <tunnel-address> '<laptop public key>'
   ```

   It prints the tunnel settings and a hosts-file line. Paste them into the laptop's tunnel, keeping
   the laptop's own `PrivateKey` line, and activate it.
3. **Add the admin site to the laptop's hosts file**
   (`C:\Windows\System32\drivers\etc\hosts` or `/etc/hosts`): paste the line
   `admin add` printed (the core's tunnel address, then `admin.getarp.internal`).

4. **Trust the admin site's certificate.** It comes from Caddy's own small CA
   on the core. Copy the CA certificate to the laptop:

   ```bash
   # on the core
   sudo cat /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
   ```

   Save it as `getarp-admin-ca.crt` on the laptop and import it as a trusted
   root (Windows: double-click → *Install certificate* → *Local machine* →
   *Trusted Root Certification Authorities*; macOS: Keychain Access → System →
   *Always trust*). Without this the site still works, with a browser warning.
5. Open **https://admin.getarp.internal** and log in.

SSH to a sensor through the tunnel:

```bash
ssh -p <ssh-port> ubuntu@<sensor tunnel address>    # addresses: sudo getarp-ctl list
```

Remove a laptop: `sudo getarp-ctl admin remove laptop1`.

## 5. Check that it works

From any machine on the internet (not your laptop's tunnel):

| Test | Expected |
|---|---|
| `ssh root@<sensor IP>` | a login prompt from the decoy; the attempt shows on the dashboard within a minute |
| `curl http://<sensor IP>/` | a fake "Admin Portal" page |
| `nc -vz <sensor IP> <ssh-port>` from an IP not allowed in | times out |
| `curl https://getarp.net/api/status` | JSON, HTTP 200 |
| `curl -i https://getarp.net/api/admin/settings` | HTTP 404 |
| `curl -i -X POST https://getarp.net/api/auth/login` | HTTP 404 |
| `curl -i https://getarp.net/api/ips/<any IP>` | HTTP 404 |

On the sensor:

```bash
sudo -u cowrie curl -m5 https://example.com      # fails: decoys have no way out
sudo -u getarp-ship curl -m5 https://example.com # fails: the shipper only reaches the core
sudo getarp-ctl status                           # all services active, recent handshake
```

On the core:

```bash
sudo getarp-ctl status
sudo tail -f /var/lib/getarp/logs/cowrie.json    # records arriving, each with "getarp_sensor"
sudo cscli decisions list                        # attackers CrowdSec has banned
```

## 6. Add more sensors

Repeat [section 3](#3-install-a-sensor) on a new machine. `getarp-ctl info`
always prints the next free address. Each sensor needs its own machine, name
and address. Nothing else changes: the new sensor's events go to the same
files and dashboard, tagged with its name.

Remove a sensor (for example if it was compromised or is being retired):

```bash
sudo getarp-ctl sensor remove s02
```

This takes effect at once: its tunnel key is removed, the firewall forgets it
and the ingest refuses it. Its collected data stays. Its name and address are
never handed out again, so give a rebuilt sensor a new name and address.

## 7. Day-to-day operations

| Task | Command (on the core unless noted) |
|---|---|
| Everything at a glance | `sudo getarp-ctl status` (also on a sensor) |
| What a new sensor or laptop needs | `sudo getarp-ctl info` |
| Every registered peer | `sudo getarp-ctl list` |
| Rebuild tunnel and firewall from the registry | `sudo getarp-ctl apply` |
| Backup now | `sudo getarp-ctl backup` (runs nightly; 7 days kept in `/var/backups/getarp`) |
| Restore a backup | see [Restoring a backup](#restoring-a-backup) below |
| Set or reset a dashboard password | `sudo getarp-ctl password <user>` |
| Service logs | `journalctl -u getarp@pipeline -f` (or `getarp-ingest`, `getarp@api`, `getarp-cowrie`, ...) |
| Restart the application | `sudo systemctl restart 'getarp@*'` |
| Update getarp | `cd getarp-intel && git pull && sudo ./install.sh core ...` with the same options (same on sensors) |
| Threat-intel keys | admin site → settings, or add `CROWDSEC_CTI_KEY=...` / `ABUSEIPDB_KEY=...` to `/etc/getarp/svc/enrichment.env` and `sudo systemctl restart getarp@enrichment` |
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
| `/etc/getarp/peers.csv` | the registry of sensors and laptops (`getarp-ctl` edits it) |
| `/etc/getarp/secrets.env` | database and Redis passwords, JWT secret (root only) |
| `/etc/getarp/app.env`, `/etc/getarp/svc/*.env` | application settings, per-service logins |
| `/etc/getarp/nftables.nft` | firewall rules (generated) |
| `/etc/wireguard/wg0.conf` | tunnel (generated) |
| `/var/lib/getarp/logs/` | sensor logs as received (`cowrie.json`, `eve.json`, `extra.json`), 7 days |
| `/var/lib/getarp/ingest/status.json` | per-sensor counters |
| `/var/backups/getarp/` | nightly database dumps |
| `/opt/getarp/` | application code and its Python environment |
| `/var/www/getarp/` | the built dashboard |
| `/etc/caddy/Caddyfile` | web server (generated) |

**Sensor**

| Path | What |
|---|---|
| `/etc/getarp/sensor.env` | settings written by the installer |
| `/etc/cowrie/` | Cowrie settings and the accepted decoy logins (`userdb.txt`) |
| `/etc/getarp/suricata.yaml`, `/etc/getarp/getarp-local.rules` | Suricata settings and getarp's own rules |
| `/var/log/getarp/{cowrie,extra,suricata}/` | the decoy and IDS logs (the shipper's buffer while the core is away) |
| `/var/lib/getarp-shipper/state.json` | how far the shipper has sent |

## 9. Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| Sensor shows `HANDSHAKE never` | `sudo getarp-ctl status` on the sensor; core security group | Open the tunnel port on the core (listed at the end of the core install). Check the sensor was registered with the key `getarp-ctl info` prints on the sensor. |
| Handshake OK, `LAST-EVENT never` | `journalctl -u getarp-shipper -n 50` on the sensor | Usually nobody has attacked yet: try `ssh root@<sensor IP>` from outside. If the shipper says "core not reachable", check `journalctl -u getarp-ingest` on the core. |
| Events in `/var/lib/getarp/logs` but not on the dashboard | `journalctl -u getarp@pipeline -n 50` | Database or Redis login errors: re-run the installer, it rewrites the logins. |
| `https://getarp.net` has no certificate | `journalctl -u caddy -n 50` | DNS must point at the core and the web ports must be open. Caddy retries by itself. |
| Admin site does not load | tunnel active? hosts line present? | ping the core's tunnel address (from the hosts-file line) from the laptop; `sudo wg show` on the core lists the laptop with a recent handshake. |
| Locked out of a sensor's SSH | | Connect the tunnel and use `ssh -p <ssh-port> user@<sensor tunnel address>`, or the cloud console. To allow a new public IP: edit `ADMIN_CIDR` in `/etc/getarp/sensor.env`, then `sudo getarp-ctl apply`. |
| Locked out of the core's SSH | cloud console | `sudo nft delete table inet getarp` opens the firewall until the next boot; re-run the installer with `--ssh-port`. |
| Your own IP got banned | `sudo cscli decisions list` on the core | `sudo cscli decisions delete --ip <your ip>`. Do not attack your own sensors from your admin IP. |
| Suricata keeps restarting | `journalctl -u getarp-suricata -n 50` | Usually memory: give the sensor 2 GB or more. |
| Disk filling up | `sudo getarp-ctl status` (Disk) | Raw events are kept 90 days, snapshots 180 days, log files 7 days. Remove old dumps in `/var/backups/getarp`. |

Install logs are in `/var/log/getarp-install.log` on each machine.

## 10. Limits of this PoC

This is a proof of concept, built to be cheap and easy to run. Known limits,
accepted on purpose:

- **One core, one database.** No high availability. Backups are local (7 days)
  unless you give `--backup-s3`. Test a restore before relying on it.
- **Public dashboard routes** (`/api/status`, `/api/map`, `/api/ips`,
  `/api/scans`, `/api/attacks`, `/api/behavior`) are open to everyone. Attacker
  IP lists are visible. Per-IP detail, reports, log-in and settings are not.
  The public page still shows the log-in menu; it simply does not work there.
- **The admin site's certificate** comes from Caddy's internal CA on the core.
  Trust it on admin laptops only.
- **Delivery from sensor to core** survives restarts and outages on either
  side (the sensor's log files are the buffer). If the core crashes hard, a
  few lines in flight can be lost. Each sensor is rate-limited; the excess is counted as `throttled`, not stored.
- **The database's `sensor` column** holds the kind of decoy (`cowrie`,
  `suricata`, `extra`). The sensor's name is in each event's raw record,
  `raw->>'getarp_sensor'`.
- **CrowdSec bans** attackers on the core only (they lose the dashboard), not on
  the sensors: sensors must keep seeing attackers.
- **Cowrie is pinned** to 3.1.7; upgrading it is a deliberate change to
  `install.sh`.
- Not included: importing data from the earlier container build; email
  alerting; multiple admin roles.
