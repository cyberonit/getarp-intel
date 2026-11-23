"""Turn one raw sensor record into one getarp event (or None to skip it).

The only place that knows each sensor tool's log format. Every event has:
ts, sensor, source, service, event_type, src_ip, src_port, dst_port, username,
password, command, signature, severity, session, raw.
"""
import ipaddress
from datetime import datetime, timezone

# Decoys listen on unprivileged ports; the sensor firewall redirects the real
# ones. Report the port the attacker actually aimed at.
REDIRECTED = {2222: 22, 2223: 23, 8080: 80, 2121: 21}
PORT_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "https", 3306: "mysql",
                6379: "redis", 8081: "http", 445: "smb", 3389: "rdp", 25: "smtp"}

COWRIE = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "download",
}
SURICATA = {"alert": "alert", "http": "request", "anomaly": "anomaly"}
EXTRA = {"connect": "connect", "login_attempt": "login_failed", "command": "command"}


def public_ip(value):
    """The address as an ipaddress object if it is a public one, else None."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return ip if ip.is_global else None


def parse_ts(value):
    if isinstance(value, str) and value:
        try:
            ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def real_port(value):
    port = as_int(value)
    return REDIRECTED.get(port, port)


def clip(value, n=500):
    return None if value is None else str(value)[:n]


def _event(rec, source, event_type, src_ip, **kw):
    ev = {
        "ts": parse_ts(rec.get("timestamp") or rec.get("ts")),
        "sensor": str(rec.get("getarp_sensor") or "unknown"),
        "source": source, "event_type": event_type, "src_ip": src_ip,
        "service": None, "src_port": None, "dst_port": None, "username": None,
        "password": None, "command": None, "signature": None, "severity": None,
        "session": None, "raw": rec,
    }
    ev.update(kw)
    if ev["service"] is None and ev["dst_port"] is not None:
        ev["service"] = PORT_SERVICE.get(ev["dst_port"], "tcp")
    return ev


def cowrie(rec):
    event_type = COWRIE.get(rec.get("eventid"))
    ip = public_ip(rec.get("src_ip"))
    if not event_type or not ip:
        return None
    command = rec.get("input")
    if event_type == "download":
        command = rec.get("url") or rec.get("filename") or rec.get("outfile")
    return _event(rec, "cowrie", event_type, ip,
                  service=rec.get("protocol") or None,
                  src_port=as_int(rec.get("src_port")), dst_port=real_port(rec.get("dst_port")),
                  username=clip(rec.get("username"), 128), password=clip(rec.get("password"), 128),
                  command=clip(command), session=clip(rec.get("session"), 64))


def suricata(rec):
    event_type = SURICATA.get(rec.get("event_type"))
    if not event_type:
        return None
    # The attacker is the public end of the flow (an alert can match a reply).
    ip, sport, dport = public_ip(rec.get("src_ip")), rec.get("src_port"), rec.get("dest_port")
    if ip is None:
        ip, sport, dport = public_ip(rec.get("dest_ip")), rec.get("dest_port"), rec.get("src_port")
    if ip is None:
        return None
    kw = {"src_port": as_int(sport), "dst_port": real_port(dport)}
    if rec.get("app_proto") and rec["app_proto"] != "failed":
        kw["service"] = rec["app_proto"]
    if event_type == "alert":
        alert = rec.get("alert") or {}
        kw["signature"] = clip(alert.get("signature"), 300)
        kw["severity"] = as_int(alert.get("severity")) or 3
    elif event_type == "request":
        http = rec.get("http") or {}
        kw["service"] = "http"
        kw["command"] = clip(f'{http.get("http_method", "")} {http.get("url", "")}'.strip())
    else:
        anomaly = rec.get("anomaly") or {}
        kw["signature"] = clip(anomaly.get("event") or anomaly.get("type"), 300)
    return _event(rec, "suricata", event_type, ip, **kw)


def extra(rec):
    event_type = EXTRA.get(rec.get("event_type"))
    ip = public_ip(rec.get("src_ip"))
    if not event_type or not ip:
        return None
    if rec.get("service") == "http" and event_type == "connect" and rec.get("command"):
        event_type = "request"
    return _event(rec, "extra", event_type, ip,
                  service=rec.get("service") or None,
                  src_port=as_int(rec.get("src_port")), dst_port=real_port(rec.get("dst_port")),
                  username=clip(rec.get("username"), 128), password=clip(rec.get("password"), 128),
                  command=clip(rec.get("command")))


BY_SOURCE = {"cowrie": cowrie, "suricata": suricata, "extra": extra}


def normalize(source, rec):
    if not isinstance(rec, dict):
        return None
    try:
        return BY_SOURCE[source](rec)
    except (KeyError, AttributeError, TypeError):
        return None
