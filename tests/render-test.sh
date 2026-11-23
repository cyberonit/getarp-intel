#!/usr/bin/env bash
# Renders the core and sensor firewall, tunnel and allowlist into a scratch
# folder (no live changes) and checks the firewall files with "nft -c".
# Run as root on any Linux box with nftables: sudo tests/render-test.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
CTL="$HERE/bin/getarp-ctl"
export GETARP_DRY_RUN=1

# ---- core
export GETARP_ETC=$T/core/etc GETARP_WG_DIR=$T/core/wg GETARP_LIB=$T/core/lib GETARP_CROWDSEC_DIR=$T/core/crowdsec
mkdir -p "$GETARP_ETC" "$GETARP_WG_DIR" "$GETARP_LIB"
echo core > "$GETARP_ETC/role"
cat > "$GETARP_ETC/core.env" <<E
PUBLIC_IP=203.0.113.10
BIND_IP=172.31.5.10
SSH_PORTS="22, 2222"
WG_PORT=51820
ADMIN_DOMAIN=admin.getarp.internal
E
wg genkey > "$GETARP_WG_DIR/private.key" 2>/dev/null || echo "YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > "$GETARP_WG_DIR/private.key"
echo "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=" > "$GETARP_WG_DIR/public.key"
K1="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA="
K2="cccccccccccccccccccccccccccccccccccccccccc0="
K3="dddddddddddddddddddddddddddddddddddddddddd4="
"$CTL" apply >/dev/null
nft -c -f "$GETARP_ETC/nftables.nft"; echo "core firewall, no peers: ok"
"$CTL" sensor add s01 10.66.0.11 "$K1" 198.51.100.21 >/dev/null
"$CTL" sensor add s02 10.66.0.12 "$K2" 198.51.100.22 >/dev/null
"$CTL" admin add laptop1 10.66.0.2 "$K3" | grep -q "Endpoint = 203.0.113.10:51820"
nft -c -f "$GETARP_ETC/nftables.nft"; echo "core firewall, 2 sensors + 1 admin: ok"
grep -q "elements = { 10.66.0.11, 10.66.0.12 }" "$GETARP_ETC/nftables.nft"
grep -q "tcp dport { 22, 2222 } accept" "$GETARP_ETC/nftables.nft"
[ "$(grep -c '^\[Peer\]' "$GETARP_WG_DIR/wg0.conf")" = 3 ]
grep -q '"198.51.100.22"' "$GETARP_CROWDSEC_DIR/parsers/s02-enrich/getarp-whitelist.yaml"
# never reuse a name, address or key
! "$CTL" sensor add s01 10.66.0.13 "$K1" 198.51.100.23 2>/dev/null
! "$CTL" sensor add s03 10.66.0.12 "$K1" 198.51.100.23 2>/dev/null
! "$CTL" sensor add s03 10.66.0.5 "$K1" 198.51.100.23 2>/dev/null
"$CTL" sensor remove s02 >/dev/null
! grep -q 10.66.0.12 "$GETARP_ETC/nftables.nft"
[ "$(grep -c '^\[Peer\]' "$GETARP_WG_DIR/wg0.conf")" = 2 ]
! "$CTL" sensor add s02b 10.66.0.12 "$K2" 198.51.100.22 2>/dev/null
nft -c -f "$GETARP_ETC/nftables.nft"; echo "core firewall after revoke: ok"
"$CTL" info | grep -q "Next free sensor addr  : 10.66.0.13"
echo "registry rules: ok"

# ---- sensor
export GETARP_ETC=$T/sensor/etc GETARP_WG_DIR=$T/sensor/wg GETARP_LIB=$T/sensor/lib
mkdir -p "$GETARP_ETC" "$GETARP_WG_DIR"
echo sensor > "$GETARP_ETC/role"
# the sensor rules name the shipper account; make a throwaway one if needed
if ! getent passwd getarp-ship >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin getarp-ship
  trap 'rm -rf "$T"; userdel getarp-ship' EXIT
fi
for cidr in "198.51.100.99/32" ""; do
  cat > "$GETARP_ETC/sensor.env" <<E
NAME=s01
TUNNEL_IP=10.66.0.11
CORE_IP=203.0.113.10
WG_PORT=51820
PUBLIC_IFACE=lo
PUBLIC_IP=198.51.100.21
ADMIN_CIDR=$cidr
E
  "$CTL" apply >/dev/null
  nft -c -f "$GETARP_ETC/nftables.nft"; echo "sensor firewall (admin cidr '${cidr}'): ok"
done
echo "all render tests passed"
