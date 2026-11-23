#!/usr/bin/env python3
"""getarp ingest: receives sensor logs on the core.

Sensors POST batches of newline-delimited JSON to https://<core>/ingest
(Caddy terminates TLS and only forwards requests from registered sensor
addresses). Each line is
    {"source": "cowrie" | "suricata" | "extra", "payload": "<one original log line>"}
and the request carries the sensor's own key:  Authorization: Bearer <key>

Who sent a batch is decided ONLY by its key, looked up (as a SHA-256 hash) in
the peers registry. Anything a sensor writes about itself is overwritten.
Accepted records are appended to one file per source in GETARP_LOG_DIR
(cowrie.json, eve.json, extra.json), each with a "getarp_sensor" field. The
pipeline and CrowdSec read those files.

A sensor sending faster than GETARP_INGEST_RATE records per second is slowed
down (the answer comes later), never dropped: its log files are the buffer.

Standard library only. Configuration comes from the environment:
    GETARP_INGEST_LISTEN   address:port, local only      (default 127.0.0.1:6000)
    GETARP_PEERS           peers registry (CSV)           (default /etc/getarp/peers.csv)
    GETARP_LOG_DIR         where accepted records go      (default /var/lib/getarp/logs)
    GETARP_INGEST_STATUS   status file, rewritten often   (default /var/lib/getarp/ingest/status.json)
    GETARP_INGEST_RATE     records per second per sensor  (default 1000)
    GETARP_INGEST_MAX_BODY largest batch, bytes           (default 8388608)
"""
import csv
import hashlib
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN = os.environ.get("GETARP_INGEST_LISTEN", "127.0.0.1:6000")
PEERS = os.environ.get("GETARP_PEERS", "/etc/getarp/peers.csv")
OUT_DIR = os.environ.get("GETARP_LOG_DIR", "/var/lib/getarp/logs")
STATUS = os.environ.get("GETARP_INGEST_STATUS", "/var/lib/getarp/ingest/status.json")
RATE = int(os.environ.get("GETARP_INGEST_RATE", "1000"))
MAX_BODY = int(os.environ.get("GETARP_INGEST_MAX_BODY", str(8 * 1024 * 1024)))

# The only files a sensor can cause to be written. A sensor names a source;
# it never names a path.
FILES = {"cowrie": "cowrie.json", "suricata": "eve.json", "extra": "extra.json"}


def log(msg):
    print(f"[ingest] {msg}", flush=True)


class Peers:
    """Enabled sensors from the registry, by key hash; reloaded when the file changes."""

    def __init__(self, path):
        self.path = path
        self.mtime = None
        self.by_hash = {}
        self.lock = threading.Lock()

    def name_for(self, key):
        with self.lock:
            try:
                mtime = os.stat(self.path).st_mtime
            except FileNotFoundError:
                self.by_hash, self.mtime = {}, None
                return None
            if mtime != self.mtime:
                by_hash = {}
                with open(self.path, newline="", encoding="utf-8") as fh:
                    for row in csv.DictReader(fh):
                        if row.get("kind") == "sensor" and row.get("enabled") == "yes":
                            by_hash[row["secret"].strip()] = row["name"].strip()
                self.by_hash, self.mtime = by_hash, mtime
                log(f"registry loaded: {len(by_hash)} enabled sensor(s)")
            return self.by_hash.get(hashlib.sha256(key.encode()).hexdigest())


class Writer:
    """Appends to the per-source files; reopens them after log rotation."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.handles = {}
        self.checked = 0.0
        self.lock = threading.Lock()

    def reopen_all(self, *_):
        with self.lock:
            for fh, _ino in self.handles.values():
                fh.close()
            self.handles = {}

    def write(self, lines_by_file):
        with self.lock:
            now = time.monotonic()
            if now - self.checked > 5:
                self.checked = now
                for fname, (fh, ino) in list(self.handles.items()):
                    try:
                        if os.stat(os.path.join(self.out_dir, fname)).st_ino == ino:
                            continue
                    except FileNotFoundError:
                        pass
                    fh.close()
                    del self.handles[fname]
            for fname, lines in lines_by_file.items():
                entry = self.handles.get(fname)
                if entry is None:
                    fh = open(os.path.join(self.out_dir, fname), "a", encoding="utf-8")
                    entry = self.handles[fname] = (fh, os.fstat(fh.fileno()).st_ino)
                entry[0].write("".join(lines))
                entry[0].flush()


class Bucket:
    """Token bucket per sensor: RATE records per second, bursts of two seconds' worth."""

    def __init__(self, rate):
        self.rate = rate
        self.tokens = float(rate * 2)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def reserve(self, n):
        """Take n tokens; return how many seconds to wait before using them."""
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.rate * 2, self.tokens + (now - self.last) * self.rate)
            self.last = now
            self.tokens -= n
            return 0.0 if self.tokens >= 0 else -self.tokens / self.rate


class Ingest:
    def __init__(self):
        self.peers = Peers(PEERS)
        self.writer = Writer(OUT_DIR)
        self.buckets = {}
        self.stats = {}
        self.lock = threading.Lock()

    def stat(self, sensor):
        with self.lock:
            return self.stats.setdefault(sensor, {
                "accepted": 0, "slowed": 0, "malformed": 0, "last_seen": None})

    def accept(self, sensor, body):
        st = self.stat(sensor)
        out, bad = {}, 0
        for raw in body.splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
                fname = FILES.get(rec.get("source")) if isinstance(rec, dict) else None
                payload = json.loads(rec["payload"]) if fname else None
            except (ValueError, KeyError, TypeError, AttributeError):
                payload = None
            if not isinstance(payload, dict):
                bad += 1
                continue
            payload["getarp_sensor"] = sensor  # overwrites anything the sensor claimed
            out.setdefault(fname, []).append(json.dumps(payload, separators=(",", ":"), default=str) + "\n")
        n = sum(len(v) for v in out.values())
        with self.lock:
            bucket = self.buckets.setdefault(sensor, Bucket(RATE))
        delay = bucket.reserve(n)
        if delay > 0:
            st["slowed"] += 1
            time.sleep(min(delay, 30))
        if out:
            self.writer.write(out)
        with self.lock:
            st["accepted"] += n
            st["malformed"] += bad
            if n:
                st["last_seen"] = int(time.time())
        return n, bad

    def status_loop(self):
        while True:
            time.sleep(2)
            tmp = STATUS + ".tmp"
            try:
                with self.lock:
                    data = json.dumps({"updated": int(time.time()), "sensors": self.stats})
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(data)
                os.replace(tmp, STATUS)
            except OSError as e:
                log(f"cannot write status file: {e}")


INGEST = Ingest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "getarp-ingest"
    sys_version = ""

    def log_message(self, *_):   # one line per batch would be noise
        pass

    def reply(self, code, obj):
        body = (json.dumps(obj) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/ingest":
            return self.reply(404, {"error": "not found"})
        auth = self.headers.get("Authorization", "")
        sensor = INGEST.peers.name_for(auth[7:].strip()) if auth.startswith("Bearer ") else None
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if sensor is None:
            self.close_connection = True
            return self.reply(401, {"error": "unknown or revoked sensor key"})
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return self.reply(413, {"error": f"send batches of at most {MAX_BODY} bytes"})
        body = self.rfile.read(length).decode("utf-8", "replace")
        accepted, bad = INGEST.accept(sensor, body)
        self.reply(200, {"sensor": sensor, "accepted": accepted, "malformed": bad})

    def do_GET(self):
        self.reply(404, {"error": "not found"})


def main():
    host, port = LISTEN.rsplit(":", 1)
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(STATUS), exist_ok=True)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    signal.signal(signal.SIGHUP, INGEST.writer.reopen_all)
    threading.Thread(target=INGEST.status_loop, daemon=True).start()
    log(f"listening on {LISTEN}, writing to {OUT_DIR}")
    server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except OSError as e:
        log(f"cannot start: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
