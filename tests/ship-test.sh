#!/usr/bin/env bash
# End-to-end check of shipper -> ingest on loopback, no root needed.
# 127.0.0.2 plays sensor s01 (registered), 127.0.0.3 an unregistered machine.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

mkdir -p "$T/core/logs" "$T/s1/cowrie" "$T/s1/extra" "$T/s1/suricata" "$T/s3/cowrie"
cat > "$T/peers.csv" <<E
kind,name,tunnel_ip,pubkey,public_ip,enabled
sensor,s01,127.0.0.2,x,198.51.100.21,yes
sensor,old,127.0.0.3,y,198.51.100.23,no
E
PORT=$((20000 + RANDOM % 20000))
GETARP_INGEST_LISTEN=127.0.0.1:$PORT GETARP_PEERS=$T/peers.csv GETARP_LOG_DIR=$T/core/logs \
  GETARP_INGEST_STATUS=$T/core/status.json python3 -I "$HERE/core/getarp-ingest.py" > "$T/ingest.log" 2>&1 &
pids+=($!)
sleep 1

# logs that exist before the shipper starts, including junk and a fake sensor name
echo '{"eventid":"cowrie.login.failed","src_ip":"192.0.2.1","username":"root","getarp_sensor":"spoofed"}' > "$T/s1/cowrie/cowrie.json"
echo 'not json' >> "$T/s1/cowrie/cowrie.json"
echo '{"event_type":"stats"}' > "$T/s1/suricata/eve.json"
echo '{"event_type":"alert","src_ip":"192.0.2.2"}' >> "$T/s1/suricata/eve.json"
echo '{"eventid":"cowrie.session.connect","src_ip":"192.0.2.9"}' > "$T/s3/cowrie/cowrie.json"

ship() { # source-ip log-root state
  GETARP_CORE=127.0.0.1:$PORT GETARP_SOURCE_IP=$1 GETARP_LOG_ROOT=$2 GETARP_SHIP_STATE=$3 \
    python3 -I "$HERE/sensor/getarp-shipper.py" >> "$T/ship-$1.log" 2>&1 &
  pids+=($!)
}
ship 127.0.0.2 "$T/s1" "$T/s1/state.json"
ship 127.0.0.3 "$T/s3" "$T/s3/state.json"
sleep 2
echo '{"service":"http","src_ip":"192.0.2.3"}' >> "$T/s1/extra/extra.json"
# rotation: rename and start a new file
mv "$T/s1/cowrie/cowrie.json" "$T/s1/cowrie/cowrie.json.1"
echo '{"eventid":"cowrie.command.input","src_ip":"192.0.2.4","input":"uname -a"}' > "$T/s1/cowrie/cowrie.json"
sleep 3

fail() { echo "FAIL: $*"; echo "--- ingest"; cat "$T/ingest.log"; exit 1; }
c=$(wc -l < "$T/core/logs/cowrie.json")
[ "$c" = 2 ] || fail "expected 2 cowrie records, got $c"
grep -q '"getarp_sensor":"s01"' "$T/core/logs/cowrie.json" || fail "sensor name not stamped"
! grep -q spoofed "$T/core/logs/cowrie.json" || fail "sensor-supplied name was kept"
! grep -q 192.0.2.9 "$T/core/logs/cowrie.json" || fail "unregistered machine got in"
[ "$(wc -l < "$T/core/logs/eve.json")" = 1 ] || fail "suricata stats should be dropped"
grep -q 192.0.2.3 "$T/core/logs/extra.json" || fail "extra record missing"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["sensors"]["s01"]; assert s["accepted"]==4, s' \
  "$T/core/status.json" || fail "status counters"
echo "delivery, stamping, rejection, rotation: ok"

# core restart: the shipper reconnects and nothing is sent twice
kill "${pids[0]}"; sleep 1
echo '{"eventid":"cowrie.login.success","src_ip":"192.0.2.5"}' >> "$T/s1/cowrie/cowrie.json"
GETARP_INGEST_LISTEN=127.0.0.1:$PORT GETARP_PEERS=$T/peers.csv GETARP_LOG_DIR=$T/core/logs \
  GETARP_INGEST_STATUS=$T/core/status.json python3 -I "$HERE/core/getarp-ingest.py" >> "$T/ingest.log" 2>&1 &
pids+=($!)
sleep 6
[ "$(wc -l < "$T/core/logs/cowrie.json")" = 3 ] || fail "after core restart expected 3 cowrie records"
echo "reconnect after core restart: ok"

# revocation: disable s01, new lines are refused
sed -i 's/^sensor,s01,\(.*\),yes$/sensor,s01,\1,no/' "$T/peers.csv"
sleep 1
echo '{"eventid":"cowrie.login.failed","src_ip":"192.0.2.6"}' >> "$T/s1/cowrie/cowrie.json"
sleep 3
! grep -q 192.0.2.6 "$T/core/logs/cowrie.json" || fail "revoked sensor still delivering"
echo "revocation: ok"
echo "all ship tests passed"
