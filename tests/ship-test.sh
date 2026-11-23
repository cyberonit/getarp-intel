#!/usr/bin/env bash
# End-to-end check of shipper -> ingest over HTTP on loopback, no root needed.
# (On a real install Caddy sits in front with HTTPS; the shipper speaks both.)
# Sensor s01 is registered; "old" is a revoked sensor; a third key is unknown.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

K1=$(openssl rand -hex 32); K2=$(openssl rand -hex 32); K3=$(openssl rand -hex 32)
h() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
mkdir -p "$T/core/logs" "$T/s1/cowrie" "$T/s1/extra" "$T/s1/suricata" "$T/s2/cowrie" "$T/s3/cowrie"
cat > "$T/peers.csv" <<E
kind,name,secret,address,enabled
sensor,s01,$(h "$K1"),198.51.100.21,yes
sensor,old,$(h "$K2"),198.51.100.22,no
admin,me,,198.51.100.99/32,yes
E
PORT=$((20000 + RANDOM % 20000))
ingest() { # [rate]
  GETARP_INGEST_RATE=${1:-1000} GETARP_INGEST_LISTEN=127.0.0.1:$PORT GETARP_PEERS=$T/peers.csv \
    GETARP_LOG_DIR=$T/core/logs GETARP_INGEST_STATUS=$T/core/status.json \
    python3 -I "$HERE/core/getarp-ingest.py" >> "$T/ingest.log" 2>&1 &
  pids+=($!)
  sleep 1
}
ship() { # key log-root state
  GETARP_CORE_URL=http://127.0.0.1:$PORT GETARP_SENSOR_KEY=$1 GETARP_LOG_ROOT=$2 GETARP_SHIP_STATE=$3 \
    python3 -I "$HERE/sensor/getarp-shipper.py" >> "$T/ship.log" 2>&1 &
  pids+=($!)
}
fail() { echo "FAIL: $*"; echo "--- ingest"; cat "$T/ingest.log"; echo "--- shipper"; tail -20 "$T/ship.log"; exit 1; }
lines() { if [ -f "$1" ]; then wc -l < "$1"; else echo 0; fi; }

ingest
# logs that exist before the shipper starts, including junk and a fake sensor name
echo '{"eventid":"cowrie.login.failed","src_ip":"192.0.2.1","username":"root","getarp_sensor":"spoofed"}' > "$T/s1/cowrie/cowrie.json"
echo 'not json' >> "$T/s1/cowrie/cowrie.json"
echo '{"event_type":"stats"}' > "$T/s1/suricata/eve.json"
echo '{"event_type":"alert","src_ip":"192.0.2.2"}' >> "$T/s1/suricata/eve.json"
echo '{"eventid":"cowrie.session.connect","src_ip":"192.0.2.8"}' > "$T/s2/cowrie/cowrie.json"
echo '{"eventid":"cowrie.session.connect","src_ip":"192.0.2.9"}' > "$T/s3/cowrie/cowrie.json"
ship "$K1" "$T/s1" "$T/s1/state.json"
ship "$K2" "$T/s2" "$T/s2/state.json"
ship "$K3" "$T/s3" "$T/s3/state.json"
sleep 2
echo '{"service":"http","src_ip":"192.0.2.3"}' >> "$T/s1/extra/extra.json"
mv "$T/s1/cowrie/cowrie.json" "$T/s1/cowrie/cowrie.json.1"          # rotation
echo '{"eventid":"cowrie.command.input","src_ip":"192.0.2.4","input":"uname -a"}' > "$T/s1/cowrie/cowrie.json"
sleep 3

[ "$(lines "$T/core/logs/cowrie.json")" = 2 ] || fail "expected 2 cowrie records, got $(lines "$T/core/logs/cowrie.json")"
grep -q '"getarp_sensor":"s01"' "$T/core/logs/cowrie.json" || fail "sensor name not stamped"
! grep -q spoofed "$T/core/logs/cowrie.json" || fail "sensor-supplied name was kept"
! grep -qE '192\.0\.2\.[89]' "$T/core/logs/cowrie.json" || fail "revoked or unknown key got in"
[ "$(lines "$T/core/logs/eve.json")" = 1 ] || fail "suricata stats should be dropped"
grep -q 192.0.2.3 "$T/core/logs/extra.json" || fail "extra record missing"
grep -q "401" "$T/ship.log" || fail "unknown keys should be told 401"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["sensors"]["s01"]; assert s["accepted"]==4, s' \
  "$T/core/status.json" || fail "status counters"
echo "delivery, stamping, refusal of unknown/revoked keys, rotation: ok"

# core down: lines written meanwhile are delivered once it is back, exactly once
kill "${pids[0]}"; wait "${pids[0]}" 2>/dev/null || true
sleep 1
echo '{"eventid":"cowrie.login.success","src_ip":"192.0.2.5"}' >> "$T/s1/cowrie/cowrie.json"
sleep 2
ingest
for _ in $(seq 1 20); do [ "$(lines "$T/core/logs/cowrie.json")" -ge 3 ] && break; sleep 0.5; done
[ "$(lines "$T/core/logs/cowrie.json")" = 3 ] || fail "after core outage expected 3 cowrie records"
echo "core outage: nothing lost, nothing repeated: ok"

# revocation: disable s01, new lines are refused
sed -i 's/^sensor,s01,\(.*\),yes$/sensor,s01,\1,no/' "$T/peers.csv"
sleep 1
echo '{"eventid":"cowrie.login.failed","src_ip":"192.0.2.6"}' >> "$T/s1/cowrie/cowrie.json"
sleep 3
! grep -q 192.0.2.6 "$T/core/logs/cowrie.json" || fail "revoked sensor still delivering"
echo "revocation: ok"

# backlog after an outage: a sensor far over its rate is slowed down, nothing is lost
kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; pids=()
sed -i 's/^sensor,s01,\(.*\),no$/sensor,s01,\1,yes/' "$T/peers.csv"
rm -f "$T"/core/logs/*.json "$T/s1/state.json"
python3 -c "
import json
with open('$T/s1/cowrie/cowrie.json', 'w') as f:
    for i in range(5000):
        f.write(json.dumps({'eventid': 'cowrie.login.failed', 'src_ip': '192.0.2.7', 'n': i}) + '\n')"
ingest 1000
ship "$K1" "$T/s1" "$T/s1/state.json"
for _ in $(seq 1 30); do [ "$(lines "$T/core/logs/cowrie.json")" -ge 5000 ] && break; sleep 0.5; done
[ "$(lines "$T/core/logs/cowrie.json")" = 5000 ] || fail "backlog: expected 5000, got $(lines "$T/core/logs/cowrie.json")"
sleep 2.5
python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["sensors"]["s01"]; assert s["slowed"] > 0, s' \
  "$T/core/status.json" || fail "the sensor should have been slowed down"
echo "backlog of 5000 at 1000/s: all delivered, sensor slowed not dropped: ok"
echo "all ship tests passed"
