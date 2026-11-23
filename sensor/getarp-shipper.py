#!/usr/bin/env python3
"""getarp shipper: sends this sensor's logs to the core over HTTPS.

It follows three JSON-lines logs (Cowrie, the extra decoys, Suricata) and
POSTs new lines in batches to the core's /ingest address as
    {"source": "<cowrie|extra|suricata>", "payload": "<the original line>"}
with this sensor's key (Authorization: Bearer ...). The core knows which
sensor this is from the key alone.

A batch counts as sent only when the core says so; until then the file
position does not move. While the core is away nothing is lost: the logs on
disk are the buffer. Positions are saved, so a restart resumes where it
stopped. Log rotation (rename or truncate) is followed.

Standard library only. Configuration comes from the environment:
    GETARP_CORE_URL     the core, e.g. https://getarp.example   (required)
    GETARP_SENSOR_KEY   this sensor's key                        (required)
    GETARP_LOG_ROOT     where the sensor logs are   (default /var/log/getarp)
    GETARP_SHIP_STATE   saved file positions        (default /var/lib/getarp-shipper/state.json)
"""
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import urlsplit

CORE_URL = os.environ.get("GETARP_CORE_URL", "")
KEY = os.environ.get("GETARP_SENSOR_KEY", "")
ROOT = os.environ.get("GETARP_LOG_ROOT", "/var/log/getarp")
STATE = os.environ.get("GETARP_SHIP_STATE", "/var/lib/getarp-shipper/state.json")
MAX_LINE = 262144
BATCH_LINES = 2000
BATCH_BYTES = 4 * 1024 * 1024

SOURCES = {
    "cowrie": "cowrie/cowrie.json",
    "extra": "extra/extra.json",
    "suricata": "suricata/eve.json",
}


def log(msg):
    print(f"[shipper] {msg}", flush=True)


class Follower:
    """Reads complete new lines from one file, remembering inode and offset."""

    def __init__(self, source, path, saved):
        self.source = source
        self.path = path
        self.inode = saved.get("inode")
        self.offset = saved.get("offset", 0)

    def state(self):
        return {"inode": self.inode, "offset": self.offset}

    def read_lines(self, max_lines, max_bytes):
        """Return (lines, new_offset); the position only moves on commit()."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return [], self.offset
        if st.st_ino != self.inode or st.st_size < self.offset:
            # New file after rotation, or truncated in place: start at its beginning.
            self.inode, self.offset = st.st_ino, 0
        if st.st_size == self.offset:
            return [], self.offset
        lines, pos, size = [], self.offset, 0
        with open(self.path, "rb") as fh:
            fh.seek(pos)
            while len(lines) < max_lines and size < max_bytes:
                chunk = fh.readline(MAX_LINE + 1)
                if not chunk:
                    break
                if not chunk.endswith(b"\n"):
                    if len(chunk) > MAX_LINE:
                        pos += len(chunk)        # oversized: skip it
                        continue
                    break                        # incomplete: wait for the writer
                pos += len(chunk)
                size += len(chunk)
                lines.append(chunk.rstrip(b"\r\n"))
        return lines, pos


def wrap(source, raw):
    """The record to send, or None for lines not worth sending."""
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    if source == "suricata" and obj.get("event_type") == "stats":
        return None
    return json.dumps({"source": source, "payload": text}, separators=(",", ":")) + "\n"


def load_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(followers):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({f.source: f.state() for f in followers}, fh)
    os.replace(tmp, STATE)


class Core:
    """One kept-alive HTTPS connection to the core's /ingest."""

    def __init__(self, url, key):
        u = urlsplit(url)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise SystemExit(f"GETARP_CORE_URL must look like https://name, not {url!r}")
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.path = (u.path.rstrip("/") or "") + "/ingest"
        self.headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/x-ndjson",
                        "User-Agent": "getarp-shipper"}
        self.ctx = ssl.create_default_context() if self.https else None
        self.conn = None

    def send(self, body):
        """POST one batch. Returns the core's answer; raises on any failure."""
        for attempt in (1, 2):   # a kept-alive connection may have been closed by the core
            if self.conn is None:
                cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
                kw = {"context": self.ctx} if self.https else {}
                self.conn = cls(self.host, self.port, timeout=60, **kw)
            try:
                self.conn.request("POST", self.path, body=body, headers=self.headers)
                resp = self.conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException):
                self.close()
                if attempt == 2:
                    raise
                continue
            if resp.status != 200:
                self.close()
                raise RuntimeError(f"core answered {resp.status}: {data[:200].decode('utf-8', 'replace')}")
            return json.loads(data or b"{}")
        return {}

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None


def main():
    if not CORE_URL or not KEY:
        log("GETARP_CORE_URL and GETARP_SENSOR_KEY must be set (see /etc/getarp/shipper.env)")
        sys.exit(2)
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    saved = load_state()
    followers = [Follower(s, os.path.join(ROOT, p), saved.get(s, {})) for s, p in SOURCES.items()]
    core = Core(CORE_URL, KEY)
    backoff, last_save, reported_ok = 1, 0.0, False
    log(f"shipping {', '.join(SOURCES)} to {CORE_URL}")
    while True:
        sent_any = False
        for f in followers:
            lines, new_offset = f.read_lines(BATCH_LINES, BATCH_BYTES)
            if new_offset == f.offset:
                continue
            body = "".join(r for r in (wrap(f.source, ln) for ln in lines) if r)
            if body:
                try:
                    core.send(body.encode())
                except (OSError, RuntimeError, ValueError, http.client.HTTPException) as e:
                    log(f"could not deliver ({e}); retrying in {backoff}s")
                    reported_ok = False
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                    break
                if not reported_ok:
                    log("delivering to the core")
                    reported_ok = True
                backoff = 1
            f.offset = new_offset     # committed: the core has it
            sent_any = True
        now = time.monotonic()
        if sent_any and now - last_save > 2:
            save_state(followers)
            last_save = now
        if not sent_any:
            time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
