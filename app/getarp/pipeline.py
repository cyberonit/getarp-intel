"""getarp pipeline: sensor logs in, events, findings and scores out.

Reads the files the ingest writes (one per log kind, all sensors mixed, each
record tagged with its sensor), and for every batch, in one transaction:
  - stores the events
  - updates each attacking address (counts, services, ports, score, class,
    country and network)
  - stores findings (scans, attacks) and what intruders typed
It remembers how far it has read, so a restart continues where it stopped.
Every minute it writes the live status the dashboard shows.

Run: python -m getarp.pipeline
"""
import asyncio
import json
import logging
import os
import time
from collections import Counter

import asyncpg

from . import config
from .detect import RANK, Detector, tactics_for
from .geo import Geo
from .normalize import normalize

log = logging.getLogger("getarp.pipeline")

FILES = {"cowrie": "cowrie.json", "suricata": "eve.json", "extra": "extra.json"}
BATCH = 1000
MAX_LINE = 262144
LIVE_CHANNEL = "getarp_live"

EVENT_COLS = ["ts", "sensor", "source", "service", "event_type", "src_ip", "src_port",
              "dst_port", "username", "password", "command", "signature", "severity",
              "session", "raw"]
FINDING_COLS = ["ts", "src_ip", "kind", "type", "service", "severity", "sensor", "detail"]
RANK_SQL = "ARRAY[" + ",".join(f"'{r}'" for r in RANK) + "]"

UPSERT_IP = f"""
INSERT INTO ips AS i (src_ip, first_seen, last_seen, events, services, ports, sensors,
                      score, class, country, asn, as_org)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (src_ip) DO UPDATE SET
  first_seen = LEAST(i.first_seen, EXCLUDED.first_seen),
  last_seen  = GREATEST(i.last_seen, EXCLUDED.last_seen),
  events     = i.events + EXCLUDED.events,
  services   = ARRAY(SELECT DISTINCT s FROM unnest(i.services || EXCLUDED.services) s ORDER BY s),
  ports      = (ARRAY(SELECT DISTINCT p FROM unnest(i.ports || EXCLUDED.ports) p ORDER BY p))[1:64],
  sensors    = ARRAY(SELECT DISTINCT s FROM unnest(i.sensors || EXCLUDED.sensors) s ORDER BY s),
  score      = GREATEST(i.score, EXCLUDED.score),
  class      = CASE WHEN array_position({RANK_SQL}, EXCLUDED.class) > array_position({RANK_SQL}, i.class)
                    THEN EXCLUDED.class ELSE i.class END,
  country    = COALESCE(EXCLUDED.country, i.country),
  asn        = COALESCE(EXCLUDED.asn, i.asn),
  as_org     = COALESCE(EXCLUDED.as_org, i.as_org)
"""

UPSERT_HOURLY = """
INSERT INTO ip_hourly AS h (bucket, src_ip, events) VALUES ($1, $2, $3)
ON CONFLICT (bucket, src_ip) DO UPDATE SET events = h.events + EXCLUDED.events
"""

UPSERT_PROFILE = """
INSERT INTO profiles AS p (src_ip, sessions, commands, tooling, tactics, updated_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (src_ip) DO UPDATE SET
  sessions = p.sessions + EXCLUDED.sessions,
  commands = (p.commands || ARRAY(SELECT c FROM unnest(EXCLUDED.commands) c
                                  WHERE c <> ALL (p.commands)))[1:50],
  tooling  = ARRAY(SELECT DISTINCT x FROM unnest(p.tooling || EXCLUDED.tooling) x ORDER BY x),
  tactics  = ARRAY(SELECT DISTINCT x FROM unnest(p.tactics || EXCLUDED.tactics) x ORDER BY x),
  updated_at = now()
"""

STATUS_SQL = """
SELECT
  (SELECT count(DISTINCT src_ip) FROM events WHERE ts > now() - interval '5 minutes') AS live_attackers,
  (SELECT count(*) FROM events WHERE ts > now() - interval '5 minutes')               AS events_5m,
  (SELECT count(DISTINCT sensor) FROM events WHERE ts > now() - interval '15 minutes') AS sensors_active,
  (SELECT count(*) FROM ips WHERE first_seen > now() - interval '5 minutes')         AS new_ips_5m,
  (SELECT count(*) FROM ips WHERE first_seen > now() - interval '24 hours')          AS new_ips_24h,
  (SELECT count(*) FROM ips)                                                         AS tracked_hosts,
  (SELECT count(*) FROM findings WHERE kind = 'attack' AND ts > now() - interval '5 minutes') AS attacks_5m
"""


def _strip_nul(obj):
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {_strip_nul(k): _strip_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_nul(v) for v in obj]
    return obj


def threat_level(attacks_5m):
    if attacks_5m > 50:
        return "critical"
    if attacks_5m > 15:
        return "high"
    if attacks_5m > 3:
        return "elevated"
    return "low"


class Follower:
    """Complete lines from one file the ingest appends to; survives rotation."""

    def __init__(self, source, path, saved):
        self.source, self.path = source, path
        self.fh = None
        self.inode = saved.get("inode")
        self.offset = saved.get("offset", 0)
        self._open_saved()

    def _open_saved(self):
        # After a restart the file we were reading may have been rotated to .1.
        for candidate in (self.path, self.path + ".1"):
            try:
                st = os.stat(candidate)
            except FileNotFoundError:
                continue
            if self.inode is not None and st.st_ino == self.inode and st.st_size >= self.offset:
                self.fh = open(candidate, "rb")
                self.fh.seek(self.offset)
                return
        self.inode, self.offset = None, 0

    def _switch_to_current(self):
        try:
            fh = open(self.path, "rb")
        except FileNotFoundError:
            return False
        if self.fh:
            self.fh.close()
        self.fh, self.inode, self.offset = fh, os.fstat(fh.fileno()).st_ino, 0
        return True

    def mark(self):
        return (self.fh, self.inode, self.offset)

    def reset(self, mark):
        """Go back to a mark (after a failed database write)."""
        fh, self.inode, self.offset = mark
        if fh is not None and not fh.closed:
            if self.fh is not fh and self.fh is not None:
                self.fh.close()
            self.fh = fh
            self.fh.seek(self.offset)
        else:  # rotated in between: find the old file again by its inode
            if self.fh is not None:
                self.fh.close()
            self.fh = None
            self._open_saved()

    def state(self):
        return {"inode": self.inode, "offset": self.offset}

    def read(self, limit):
        if self.fh is None and not self._switch_to_current():
            return []
        out = []
        while len(out) < limit:
            line = self.fh.readline(MAX_LINE + 1)
            if line.endswith(b"\n"):
                self.offset += len(line)
                out.append(line)
                continue
            if len(line) > MAX_LINE:              # oversized: skip it
                self.offset += len(line)
                continue
            self.fh.seek(self.offset)              # nothing more, or half a line
            try:
                st = os.stat(self.path)
            except FileNotFoundError:
                break
            if st.st_ino != self.inode:            # rotated: the old file is finished
                self._switch_to_current()
                continue
            if st.st_size < self.offset:           # truncated
                self.fh.seek(0)
                self.offset = 0
                continue
            break
        return out


class Pipeline:
    def __init__(self, pool):
        self.pool = pool
        self.detector = Detector()
        self.geo = Geo()
        self.state_file = os.path.join(config.STATE_DIR, "offsets.json")
        saved = self._load_state()
        self.followers = [Follower(src, os.path.join(config.LOG_DIR, name), saved.get(src, {}))
                          for src, name in FILES.items()]
        self.timescale = False

    def _load_state(self):
        try:
            with open(self.state_file, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({f.source: f.state() for f in self.followers}, fh)
        os.replace(tmp, self.state_file)

    def read_batch(self):
        events = []
        for f in self.followers:
            for line in f.read(BATCH - len(events)):
                try:
                    rec = _strip_nul(json.loads(line))
                except ValueError:
                    continue
                ev = normalize(f.source, rec)
                if ev:
                    events.append(ev)
        return events

    async def write(self, events):
        per_ip, hourly, findings = {}, Counter(), []
        for ev in events:
            ip = ev["src_ip"]
            res = self.detector.observe(ev)
            a = per_ip.get(ip)
            if a is None:
                a = per_ip[ip] = {"first": ev["ts"], "last": ev["ts"], "n": 0, "services": set(),
                                  "ports": set(), "sensors": set(), "score": 0.0, "cls": "prober",
                                  "sessions": 0, "commands": [], "tooling": set()}
            a["first"], a["last"] = min(a["first"], ev["ts"]), max(a["last"], ev["ts"])
            a["n"] += 1
            if ev["service"]:
                a["services"].add(ev["service"])
            if ev["dst_port"]:
                a["ports"].add(ev["dst_port"])
            a["sensors"].add(ev["sensor"])
            a["score"] = max(a["score"], res.score)
            if RANK.index(res.cls) > RANK.index(a["cls"]):
                a["cls"] = res.cls
            a["sessions"] += res.sessions
            for c in res.commands:
                if c not in a["commands"]:
                    a["commands"].append(c)
            a["tooling"] |= res.tooling
            findings.extend(res.findings)
            hourly[(ev["ts"].replace(minute=0, second=0, microsecond=0), ip)] += 1

        event_rows = [tuple(json.dumps(ev[c], default=str, separators=(",", ":")) if c == "raw" else ev[c]
                            for c in EVENT_COLS) for ev in events]
        ip_rows, profile_rows = [], []
        for ip, a in per_ip.items():
            country, asn, org = self.geo.lookup(ip)
            ip_rows.append((ip, a["first"], a["last"], a["n"], sorted(a["services"]),
                            sorted(a["ports"])[:64], sorted(a["sensors"]), a["score"], a["cls"],
                            country, asn, org))
            if a["sessions"] or a["commands"] or a["tooling"]:
                profile_rows.append((ip, a["sessions"], a["commands"][:50], sorted(a["tooling"]),
                                     tactics_for(a["tooling"])))
        finding_rows = [(f.ts, f.src_ip, f.kind, f.type, f.service, f.severity, f.sensor,
                         json.dumps(_strip_nul(f.detail), default=str)) for f in findings]

        async with self.pool.acquire() as con:
            async with con.transaction():
                await con.copy_records_to_table("events", records=event_rows, columns=EVENT_COLS)
                await con.executemany(UPSERT_IP, ip_rows)
                await con.executemany(UPSERT_HOURLY, [(b, ip, n) for (b, ip), n in hourly.items()])
                if profile_rows:
                    await con.executemany(UPSERT_PROFILE, profile_rows)
                if finding_rows:
                    await con.copy_records_to_table("findings", records=finding_rows,
                                                    columns=FINDING_COLS)
                    # live feed: delivered to the dashboard when this commits
                    for f in findings[-20:]:
                        payload = {"type": "finding", "ts": f.ts.isoformat(), "src_ip": str(f.src_ip),
                                   "kind": f.kind, "label": f.type, "service": f.service,
                                   "severity": f.severity, "sensor": f.sensor}
                        await con.execute("SELECT pg_notify($1, $2)", LIVE_CHANNEL, json.dumps(payload))
        return len(findings)

    async def status(self):
        async with self.pool.acquire() as con:
            row = dict(await con.fetchrow(STATUS_SQL))
            data = {
                "live_attackers": row["live_attackers"],
                "events_per_min": round(row["events_5m"] / 5, 1),
                "new_ips_5m": row["new_ips_5m"],
                "new_ips_24h": row["new_ips_24h"],
                "tracked_hosts": row["tracked_hosts"],
                "attacks_5m": row["attacks_5m"],
                "sensors_active": row["sensors_active"],
                "threat_level": threat_level(row["attacks_5m"]),
            }
            text = json.dumps(data)
            await con.execute("INSERT INTO status (ts, data) VALUES (now(), $1::jsonb) "
                              "ON CONFLICT (ts) DO NOTHING", text)
            await con.execute("SELECT pg_notify($1, $2)", LIVE_CHANNEL,
                              json.dumps({"type": "status", **data}))

    async def housekeeping(self):
        tracked = self.detector.evict_idle()
        async with self.pool.acquire() as con:
            gone = await con.execute(
                "DELETE FROM ips WHERE src_ip IN (SELECT src_ip FROM ips "
                "WHERE last_seen < now() - interval '180 days' LIMIT 20000)")
            if not self.timescale:   # TimescaleDB has its own retention policies
                for sql in ("DELETE FROM events WHERE ts < now() - interval '90 days'",
                            "DELETE FROM ip_hourly WHERE bucket < now() - interval '90 days'",
                            "DELETE FROM findings WHERE ts < now() - interval '180 days'",
                            "DELETE FROM status WHERE ts < now() - interval '30 days'"):
                    await con.execute(sql)
        log.info("housekeeping: %d addresses in memory; old addresses removed: %s",
                 tracked, gone.split()[-1])

    async def run(self):
        async with self.pool.acquire() as con:
            self.timescale = bool(await con.fetchval(
                "SELECT count(*) FROM pg_extension WHERE extname = 'timescaledb'"))
        log.info("reading %s (TimescaleDB: %s)", config.LOG_DIR, "yes" if self.timescale else "no")
        last_status = last_house = 0.0
        stored = found = 0
        saved_offsets = None
        last_report = time.monotonic()
        while True:
            marks = [f.mark() for f in self.followers]
            events = self.read_batch()
            if events:
                try:
                    found += await self.write(events)
                    stored += len(events)
                except (asyncpg.PostgresError, OSError) as e:
                    log.error("database write failed, will retry: %s", e)
                    for f, m in zip(self.followers, marks):
                        f.reset(m)
                    await asyncio.sleep(5)
                    continue
            offsets = [f.state() for f in self.followers]
            if offsets != saved_offsets:
                self._save_state()
                saved_offsets = offsets
            now = time.monotonic()
            try:
                if now - last_status >= 60:
                    last_status = now
                    await self.status()
                if now - last_house >= 3600:
                    last_house = now
                    await self.housekeeping()
            except (asyncpg.PostgresError, OSError) as e:
                log.error("status/housekeeping failed: %s", e)
            if now - last_report >= 300:
                log.info("last 5 min: %d events stored, %d findings", stored, found)
                stored = found = 0
                last_report = now
            if len(events) < BATCH:
                await asyncio.sleep(0.5)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    os.makedirs(config.STATE_DIR, exist_ok=True)
    pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=2)
    await Pipeline(pool).run()


if __name__ == "__main__":
    asyncio.run(main())
