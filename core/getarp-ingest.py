#!/usr/bin/env python3
"""getarp ingest: receives sensor logs on the core, through the WireGuard tunnel.

Each sensor pushes newline-delimited JSON records of the form
    {"source": "cowrie" | "suricata" | "extra", "payload": "<one original log line>"}

Who sent a record is decided ONLY by the tunnel address it arrived from, looked
up in the peers file. WireGuard binds each tunnel address to one sensor's key,
so a sensor cannot pretend to be another one. Anything a sensor writes about
itself is overwritten.

Accepted records are appended to one file per source in OUT_DIR
(cowrie.json, eve.json, extra.json), with a "getarp_sensor" field added. The
pipeline and CrowdSec read those files exactly as they read local sensor logs.

Standard library only. Configuration comes from the environment:
    GETARP_INGEST_LISTEN   address:port to listen on      (default 10.66.0.1:6000)
    GETARP_PEERS           peers registry (CSV)           (default /etc/getarp/peers.csv)
    GETARP_LOG_DIR         where accepted records go      (default /var/lib/getarp/logs)
    GETARP_INGEST_STATUS   status file, rewritten often   (default /var/lib/getarp/ingest/status.json)
    GETARP_INGEST_RATE     records per second per sensor  (default 500)
    GETARP_INGEST_MAX_LINE longest accepted line, bytes   (default 262144)
"""
import asyncio
import csv
import json
import os
import signal
import sys
import time

LISTEN = os.environ.get("GETARP_INGEST_LISTEN", "10.66.0.1:6000")
PEERS = os.environ.get("GETARP_PEERS", "/etc/getarp/peers.csv")
OUT_DIR = os.environ.get("GETARP_LOG_DIR", "/var/lib/getarp/logs")
STATUS = os.environ.get("GETARP_INGEST_STATUS", "/var/lib/getarp/ingest/status.json")
RATE = int(os.environ.get("GETARP_INGEST_RATE", "500"))
MAX_LINE = int(os.environ.get("GETARP_INGEST_MAX_LINE", "262144"))

# The only files a sensor can cause to be written. A sensor names a source;
# it never names a path.
FILES = {"cowrie": "cowrie.json", "suricata": "eve.json", "extra": "extra.json"}


def log(msg):
    print(f"[ingest] {msg}", flush=True)


class Peers:
    """Enabled sensors from the peers CSV, reloaded when the file changes."""

    def __init__(self, path):
        self.path = path
        self.mtime = None
        self.by_ip = {}

    def refresh(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            self.by_ip, self.mtime = {}, None
            return
        if mtime == self.mtime:
            return
        by_ip = {}
        with open(self.path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("kind") == "sensor" and row.get("enabled") == "yes":
                    by_ip[row["tunnel_ip"].strip()] = row["name"].strip()
        self.by_ip, self.mtime = by_ip, mtime
        log(f"peers loaded: {len(by_ip)} enabled sensor(s)")

    def name_of(self, ip):
        self.refresh()
        return self.by_ip.get(ip)


class Writer:
    """Appends to the per-source files and reopens them after log rotation."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.handles = {}
        self.checked = 0.0

    def _open(self, fname):
        path = os.path.join(self.out_dir, fname)
        fh = open(path, "a", encoding="utf-8")
        self.handles[fname] = (fh, os.fstat(fh.fileno()).st_ino)
        return fh

    def reopen_all(self):
        for fh, _ in self.handles.values():
            fh.close()
        self.handles = {}

    def _check_rotation(self):
        now = time.monotonic()
        if now - self.checked < 5:
            return
        self.checked = now
        for fname, (fh, ino) in list(self.handles.items()):
            try:
                if os.stat(os.path.join(self.out_dir, fname)).st_ino == ino:
                    continue
            except FileNotFoundError:
                pass
            fh.close()
            del self.handles[fname]

    def write(self, fname, line):
        self._check_rotation()
        entry = self.handles.get(fname)
        fh = entry[0] if entry else self._open(fname)
        fh.write(line + "\n")

    def flush(self):
        for fh, _ in self.handles.values():
            fh.flush()


class Bucket:
    """Token bucket: RATE records per second, bursts up to two seconds' worth."""

    def __init__(self, rate):
        self.rate = rate
        self.tokens = float(rate * 2)
        self.last = time.monotonic()

    def take(self):
        now = time.monotonic()
        self.tokens = min(self.rate * 2, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Ingest:
    def __init__(self):
        self.peers = Peers(PEERS)
        self.writer = Writer(OUT_DIR)
        self.buckets = {}
        self.stats = {}

    def _stat(self, sensor):
        return self.stats.setdefault(sensor, {
            "accepted": 0, "throttled": 0, "malformed": 0, "last_seen": None})

    def handle_line(self, sensor, raw):
        st = self._stat(sensor)
        try:
            rec = json.loads(raw)
            source = rec.get("source") if isinstance(rec, dict) else None
            fname = FILES.get(source) if isinstance(source, str) else None
            payload = json.loads(rec["payload"]) if fname else None
        except (ValueError, KeyError, TypeError):
            payload = None
        if not isinstance(payload, dict):
            st["malformed"] += 1
            return
        bucket = self.buckets.setdefault(sensor, Bucket(RATE))
        if not bucket.take():
            st["throttled"] += 1
            return
        payload["getarp_sensor"] = sensor  # overwrites anything the sensor claimed
        self.writer.write(fname, json.dumps(payload, separators=(",", ":"), default=str))
        st["accepted"] += 1
        st["last_seen"] = int(time.time())

    @staticmethod
    async def _discard_line(reader, consumed):
        while True:
            await reader.readexactly(consumed)
            try:
                await reader.readuntil(b"\n")
                return
            except asyncio.LimitOverrunError as e:
                consumed = e.consumed

    async def client(self, reader, writer):
        peer_ip = (writer.get_extra_info("peername") or ("", 0))[0]
        sensor = self.peers.name_of(peer_ip)
        if sensor is None:
            # Unknown or revoked: close quietly, write nothing.
            writer.close()
            return
        log(f"{sensor} connected from {peer_ip}")
        try:
            while True:
                try:
                    line = await reader.readuntil(b"\n")
                except asyncio.LimitOverrunError as e:
                    # Oversized line: throw it away up to the next newline.
                    self._stat(sensor)["malformed"] += 1
                    await self._discard_line(reader, e.consumed)
                    continue
                if self.peers.name_of(peer_ip) != sensor:
                    log(f"{sensor} was revoked; closing its connection")
                    break
                self.handle_line(sensor, line.decode("utf-8", "replace").strip())
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.writer.flush()
            writer.close()
            log(f"{sensor} disconnected")

    async def housekeeping(self):
        while True:
            await asyncio.sleep(2)
            self.writer.flush()
            tmp = STATUS + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"updated": int(time.time()), "sensors": self.stats}, fh)
                os.replace(tmp, STATUS)
            except OSError as e:
                log(f"cannot write status file: {e}")

    async def run(self):
        host, port = LISTEN.rsplit(":", 1)
        os.makedirs(OUT_DIR, exist_ok=True)
        self.peers.refresh()
        server = await asyncio.start_server(self.client, host, int(port), limit=MAX_LINE)
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, self.writer.reopen_all)
        log(f"listening on {LISTEN}, writing to {OUT_DIR}")
        async with server:
            await asyncio.gather(server.serve_forever(), self.housekeeping())


if __name__ == "__main__":
    try:
        asyncio.run(Ingest().run())
    except OSError as e:
        # Most often: the tunnel address does not exist yet. systemd restarts us.
        log(f"cannot start: {e}")
        sys.exit(1)
