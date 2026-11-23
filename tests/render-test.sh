#!/usr/bin/env bash
# Renders the core and sensor firewall, the web server config and the CrowdSec
# allowlist into a scratch folder (no live changes), then checks them with
# "nft -c" and "caddy validate". Run as root on a box with nftables and caddy:
#   sudo tests/render-test.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT
CTL="$HERE/bin/getarp-ctl"
export GETARP_DRY_RUN=1
fail() { echo "FAIL: $*"; exit 1; }
caddy_ok() { caddy validate --adapter caddyfile --config "$1" >/dev/null 2>&1 || { caddy validate --adapter caddyfile --config "$1"; fail "caddy config invalid"; }; }

# ---- core
export GETARP_ETC=$T/core/etc GETARP_LIB=$T/core/lib GETARP_CROWDSEC_DIR=$T/core/crowdsec \
  GETARP_CADDYFILE=$T/core/caddy/Caddyfile
mkdir -p "$GETARP_ETC" "$GETARP_LIB" "$T/core/caddy"
echo core > "$GETARP_ETC/role"
cat > "$GETARP_ETC/core.env" <<E
DOMAIN=getarp.example
EMAIL=ops@example.com
PUBLIC_IP=203.0.113.10
BIND_IP=127.0.0.1
SSH_PORTS="22, 2222"
PG_MAJOR=17
E
"$CTL" apply >/dev/null
nft -c -f "$GETARP_ETC/nftables.nft"; echo "core firewall: ok"
caddy_ok "$GETARP_CADDYFILE"
! grep -q "@sensors\|@admin_api" "$GETARP_CADDYFILE" || fail "no sensors/admins yet: no such routes"
echo "web server, nothing registered: ok"

out=$("$CTL" sensor add s01 198.51.100.21)
key=$(echo "$out" | awk '/^    [0-9a-f]{64}$/ {print $1}')
[ ${#key} = 64 ] || fail "sensor add should print a 64-hex key"
echo "$out" | grep -q "install.sh sensor --core https://getarp.example --key $key" || fail "install command"
grep -q "$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)" "$GETARP_ETC/peers.csv" || fail "key hash stored"
! grep -q "$key" "$GETARP_ETC/peers.csv" || fail "the key itself must not be stored"
"$CTL" sensor add s02 198.51.100.22 >/dev/null
"$CTL" admin add office 203.0.113.0/24 >/dev/null
"$CTL" admin add me 198.51.100.99 >/dev/null
caddy_ok "$GETARP_CADDYFILE"
grep -q "remote_ip 198.51.100.21 198.51.100.22" "$GETARP_CADDYFILE" || fail "sensor allowlist"
grep -q "remote_ip 203.0.113.0/24 198.51.100.99" "$GETARP_CADDYFILE" || fail "admin allowlist"
grep -q '"198.51.100.22"' "$GETARP_CROWDSEC_DIR/parsers/s02-enrich/getarp-whitelist.yaml" || fail "crowdsec ip"
grep -q '"198.51.100.99/32"' "$GETARP_CROWDSEC_DIR/parsers/s02-enrich/getarp-whitelist.yaml" || fail "crowdsec cidr"
echo "web server and allowlist with 2 sensors, 2 admin addresses: ok"

! "$CTL" sensor add s01 198.51.100.23 2>/dev/null || fail "a name must not be reused"
! "$CTL" sensor add "Bad Name" 198.51.100.23 2>/dev/null || fail "bad name accepted"
! "$CTL" admin add x1 999.1.1.1 2>/dev/null || fail "bad address accepted"
"$CTL" sensor move s02 198.51.100.44 >/dev/null
grep -q "remote_ip 198.51.100.21 198.51.100.44" "$GETARP_CADDYFILE" || fail "move"
"$CTL" sensor remove s02 >/dev/null
! grep -q 198.51.100.44 "$GETARP_CADDYFILE" || fail "removed sensor still allowed"
! "$CTL" sensor add s02 198.51.100.44 2>/dev/null || fail "a removed name must not come back"
"$CTL" admin remove office >/dev/null
caddy_ok "$GETARP_CADDYFILE"
echo "registry rules (no reuse, move, revoke): ok"

# ---- sensor
export GETARP_ETC=$T/sensor/etc GETARP_LIB=$T/sensor/lib
mkdir -p "$GETARP_ETC"
echo sensor > "$GETARP_ETC/role"
# the sensor rules name the shipper account; make a throwaway one if needed
if ! getent passwd getarp-ship >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin getarp-ship
  trap 'cleanup; userdel getarp-ship' EXIT
fi
for cidr in "198.51.100.99/32" "198.51.100.99/32,203.0.113.0/24" ""; do
  cat > "$GETARP_ETC/sensor.env" <<E
CORE_URL=https://getarp.example
CORE_IP=203.0.113.10
PUBLIC_IFACE=lo
PUBLIC_IP=198.51.100.21
ADMIN_CIDR=$cidr
E
  "$CTL" apply >/dev/null
  nft -c -f "$GETARP_ETC/nftables.nft"; echo "sensor firewall (admin '${cidr}'): ok"
done
echo "all render tests passed"
