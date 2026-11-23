#!/usr/bin/env python3
"""getarp shipper: pushes this sensor's logs to the core, through the tunnel.

It follows three JSON-lines logs (Cowrie, the extra decoys, Suricata) and sends
each new line to the core's ingest as
    {"source": "<cowrie|extra|suricata>", "payload": "<the original line>"}

Telemetry only ever flows one way, from here to the core. The sensor does not
say who it is: the core knows from the tunnel address.

While the core is unreachable nothing is read, so the logs on disk are the
buffer. File positions are saved, so a restart resumes where it stopped.
Log rotation (rename or truncate) is followed.

Standard library only. Configuration comes from the environment:
    GETARP_CORE         core ingest address:port   (default 10.66.0.1:6000)
    GETARP_LOG_ROOT     where the sensor logs are  (default /var/log/getarp)
    GETARP_SHIP_STATE   saved file positions        (default /var/lib/getarp-shipper/state.json)
    GETARP_SOURCE_IP    bind to this local address before connecting (tests only)
"""
import json
import os
import socket
import sys
import time

CORE = os.environ.get("GETARP_CORE", "10.66.0.1:6000")
ROOT = os.environ.get("GETARP_LOG_ROOT", "/var/log/getarp")
STATE = os.environ.get("GETARP_SHIP_STATE", "/var/lib/getarp-shipper/state.json")
SOURCE_IP = os.environ.get("GETARP_SOURCE_IP", "")
MAX_LINE = 262144
BATCH = 500

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
        self.partial = b""

    def state(self):
        return {"inode": self.inode, "offset": self.offset}

    def read_lines(self, limit):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        if st.st_ino != self.inode or st.st_size < self.offset:
            # New file after rotation, or truncated in place: start at its beginning.
            self.inode, self.offset, self.partial = st.st_ino, 0, b""
        if st.st_size == self.offset:
            return []
        lines = []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while len(lines) < limit:
                chunk = fh.readline(MAX_LINE + 1)
                if not chunk:
                    break
                if not chunk.endswith(b"\n"):
                    if len(chunk) > MAX_LINE:
                        self.offset += len(chunk)  # oversized: skip it
                        continue
                    break  # an incomplete line: wait for the writer to finish it
                self.offset += len(chunk)
                lines.append(chunk.rstrip(b"\r\n"))
        return lines


def wrap(source, raw):
    """Return the record to send, or None for lines that are not worth sending."""
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    if source == "suricata" and obj.get("event_type") == "stats":
        return None
    return (json.dumps({"source": source, "payload": text}, separators=(",", ":")) + "\n").encode()


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


def connect():
    host, port = CORE.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.settimeout(10)
    if SOURCE_IP:
        sock.bind((SOURCE_IP, 0))
    sock.connect((host, int(port)))
    return sock


def alive(sock):
    """False once the core has closed its end. The core never sends anything,
    so readable-with-no-data means closed. Checked before every send, so lines
    are not written into a connection that is already gone."""
    try:
        sock.setblocking(False)
        try:
            return sock.recv(1, socket.MSG_PEEK) != b""
        except (BlockingIOError, InterruptedError):
            return True
        finally:
            sock.settimeout(10)
    except OSError:
        return False


def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    saved = load_state()
    followers = [Follower(s, os.path.join(ROOT, p), saved.get(s, {})) for s, p in SOURCES.items()]
    sock, backoff, last_save = None, 1, 0.0
    log(f"shipping {', '.join(SOURCES)} to {CORE}")
    while True:
        if sock is None:
            try:
                sock = connect()
                log("connected to the core")
            except OSError as e:
                log(f"core not reachable ({e}); retrying in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
        if not alive(sock):
            log(f"the core closed the connection; reconnecting in {backoff}s")
            sock.close()
            sock = None
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        sent_any = False
        try:
            for f in followers:
                before = f.state()
                lines = f.read_lines(BATCH)
                if not lines:
                    continue
                data = b"".join(r for r in (wrap(f.source, ln) for ln in lines) if r)
                try:
                    if data:
                        sock.sendall(data)
                except OSError:
                    # Not sent: rewind so these lines go out after reconnecting.
                    f.inode, f.offset = before["inode"], before["offset"]
                    raise
                sent_any = True
        except OSError as e:
            log(f"connection lost ({e}); reconnecting")
            try:
                sock.close()
            finally:
                sock = None
            continue
        if sent_any:
            backoff = 1
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
