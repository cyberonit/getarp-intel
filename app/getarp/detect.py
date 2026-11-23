"""Correlation: turns a stream of events into findings, scores and profiles.

State is kept per address in memory, for a few minutes only. Anything durable
(score, class, profile) is merged into the database by the pipeline, so a
restart loses nothing but the short sliding windows.
"""
import re
import time
from collections import deque
from dataclasses import dataclass, field

from . import config

RANK = ["prober", "scanner", "bruteforcer", "intruder", "exploiter"]

EVENT_SCORE = {"connect": 5, "request": 10, "anomaly": 15, "login_failed": 20,
               "login_success": 50, "command": 65, "download": 85}
EVENT_CLASS = {"login_success": "intruder", "command": "intruder", "download": "exploiter"}
ALERT_SCORE = {1: 75, 2: 55, 3: 35}          # Suricata severity 1 is the worst
ALERT_SEVERITY = {1: 4, 2: 3, 3: 2}

TOOLING = {
    "mirai": re.compile(r"/bin/busybox|mirai|\.(mips|mpsl|arm7?|x86)\b", re.I),
    "cryptominer": re.compile(r"xmrig|minerd|stratum\+tcp|c3pool|nanopool", re.I),
    "downloader": re.compile(r"\b(wget|curl|tftp|ftpget)\b", re.I),
    "recon": re.compile(r"\b(uname|whoami|nproc|lscpu|free -m|cat /proc/cpuinfo|ifconfig|ip a)\b", re.I),
    "persistence": re.compile(r"crontab|authorized_keys|/etc/rc\.local|systemctl enable", re.I),
    "cleanup": re.compile(r"history -c|rm -rf /tmp|unset HISTFILE", re.I),
}
TACTICS = {"recon": "Discovery", "downloader": "Command and Control",
           "mirai": "Execution", "cryptominer": "Impact",
           "persistence": "Persistence", "cleanup": "Defense Evasion"}
HARMFUL_TOOLING = {"mirai": 90, "cryptominer": 90}

MAX_COMMANDS = 50
IDLE_EVICT = 900       # forget an address after 15 quiet minutes
DEDUPE = 600           # one finding of a kind per address per 10 minutes


@dataclass
class Finding:
    ts: object
    src_ip: object
    kind: str            # scan | attack
    type: str
    severity: int
    service: str | None
    sensor: str
    detail: dict


@dataclass
class Result:
    score: float = 0.0
    cls: str = "prober"
    findings: list = field(default_factory=list)
    sessions: int = 0
    commands: list = field(default_factory=list)
    tooling: set = field(default_factory=set)

    def raise_to(self, score, cls):
        self.score = max(self.score, score)
        if RANK.index(cls) > RANK.index(self.cls):
            self.cls = cls


class _State:
    __slots__ = ("touched", "ports", "logins", "reported")

    def __init__(self):
        self.touched = time.monotonic()
        self.ports = deque(maxlen=200)     # (t, port)
        self.logins = deque(maxlen=500)    # (t, username)
        self.reported = {}                 # tag -> t


class Detector:
    def __init__(self):
        self.states = {}

    def evict_idle(self):
        cutoff = time.monotonic() - IDLE_EVICT
        for ip in [ip for ip, s in self.states.items() if s.touched < cutoff]:
            del self.states[ip]
        return len(self.states)

    def _once(self, st, tag, t, window=DEDUPE):
        last = st.reported.get(tag)
        if last is not None and 0 <= t - last < window:
            return False
        st.reported[tag] = t
        if len(st.reported) > 200:
            st.reported.pop(next(iter(st.reported)))
        return True

    def observe(self, ev):
        """Process one event; return a Result for its address."""
        ip, et, t = ev["src_ip"], ev["event_type"], ev["ts"].timestamp()
        st = self.states.get(ip)
        if st is None:
            st = self.states[ip] = _State()
        st.touched = time.monotonic()
        res = Result()
        res.raise_to(EVENT_SCORE.get(et, 5), EVENT_CLASS.get(et, "prober"))

        def find(kind, ftype, severity, detail):
            res.findings.append(Finding(ev["ts"], ip, kind, ftype, severity, ev["service"],
                                        ev["sensor"], detail))

        # many different ports in a short time: a sweep of the decoys
        if ev["dst_port"]:
            st.ports.append((t, ev["dst_port"]))
            ports = sorted({p for (pt, p) in st.ports if t - pt <= config.SWEEP_WINDOW})
            if len(ports) >= config.SWEEP_PORTS and self._once(st, "sweep", t, config.SWEEP_WINDOW):
                find("scan", "service_sweep", 1, {"ports": ports, "window_s": config.SWEEP_WINDOW})
                res.raise_to(30, "scanner")

        if et == "login_failed":
            st.logins.append((t, ev["username"]))
            recent = [u for (lt, u) in st.logins if t - lt <= config.BRUTE_WINDOW]
            if len(recent) >= config.BRUTE_ATTEMPTS and self._once(st, "brute", t, config.BRUTE_WINDOW):
                users = sorted({u for u in recent if u})
                ftype = "credential_stuffing" if len(users) > 3 else "bruteforce"
                find("attack", ftype, 2, {"attempts": len(recent), "usernames": users[:20],
                                          "window_s": config.BRUTE_WINDOW})
                res.raise_to(50 if ftype == "credential_stuffing" else 45, "bruteforcer")

        elif et == "login_success":
            if self._once(st, "access", t):
                find("attack", "access", 3, {"username": ev["username"], "password": ev["password"]})

        elif et == "command" and ev["command"]:
            cmd = ev["command"][:300]
            res.commands.append(cmd)
            for name, rx in TOOLING.items():
                if rx.search(cmd):
                    res.tooling.add(name)
                    if name in HARMFUL_TOOLING:
                        res.raise_to(HARMFUL_TOOLING[name], "exploiter")
            if self._once(st, "cmd:" + str(ev["session"] or ""), t):
                find("attack", "command_exec", 3, {"command": cmd, "session": ev["session"]})

        elif et == "download":
            if self._once(st, "dl:" + str(ev["command"]), t):
                find("attack", "malware_download", 4, {"url": ev["command"]})

        elif et == "alert":
            sev = ev["severity"] or 3
            res.raise_to(ALERT_SCORE.get(sev, 35), "prober")
            if self._once(st, "ids:" + str(ev["signature"]), t):
                find("attack", "ids_alert", ALERT_SEVERITY.get(sev, 2),
                     {"signature": ev["signature"]})

        if et == "connect" and ev["source"] == "cowrie":
            res.sessions = 1
        return res


def tactics_for(tooling):
    return sorted({TACTICS[t] for t in tooling if t in TACTICS})
