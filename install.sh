#!/usr/bin/env bash
# getarp PoC installer: Ubuntu 24.04 LTS on amd64 or arm64. No containers.
#
#   Core (the dashboard, database and analysis; install this first):
#     sudo ./install.sh core --domain getarp.net --email you@example.com
#
#   Sensor (a honeypot; as many as you like, each on its own machine). First
#   register it on the core, which prints this exact command with its key:
#     sudo getarp-ctl sensor add s01 <sensor public ip>                (on the core)
#     sudo ./install.sh sensor --core https://getarp.net --key <key>   (on the sensor)
#
#   Safe to run again: keys, passwords and data are kept.
#
# Options, core:
#   --domain NAME        public name of the dashboard (DNS must point here)   [required]
#   --email ADDRESS      contact for the Let's Encrypt certificate              [required]
#   --admin-user NAME    first dashboard login (default: admin)
#   --admin-cidr CIDR    where admins sign in from, comma separated (default: the
#                        address you are connected from; more later: getarp-ctl admin add)
#   --public-ip IP       this machine's public address (default: detected)
#   --bind-ip IP         local address the site listens on (default: detected)
#   --ssh-port N         SSH port(s) to keep open, comma separated (default: detected)
#   --backup-s3 URI      also copy the nightly backup to s3://bucket/prefix (optional)
#
# Options, sensor:
#   --core URL           the core, e.g. https://getarp.net                     [required]
#   --key KEY            this sensor's key, from "getarp-ctl sensor add"        [required]
#   --admin-cidr CIDR    who may reach the real SSH from the internet, comma separated
#                        (default: the address you are connected from)
#   --iface NAME         public network interface (default: detected)
#   --public-ip IP       this machine's public address (default: detected)
# shellcheck disable=SC2015
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PG_MAJOR=17
COWRIE_REPO=https://github.com/cowrie/cowrie.git
COWRIE_REF=v3.1.7
COWRIE_COMMIT=8e36327f6a24abe379dac807cc7e8b2d2fb01248
INSTALL_LOG=/var/log/getarp-install.log

ETC=/etc/getarp
OPT=/opt/getarp
export DEBIAN_FRONTEND=noninteractive

STEP=0
step() { STEP=$((STEP + 1)); printf '\n\033[1m[%d] %s\033[0m\n' "$STEP" "$*"; }
say() { echo "    $*"; }
warn() { printf '\033[33m    warning: %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }
usage() { sed -n "2,/^set -euo/p" "$0" | grep "^#" | grep -v "shellcheck" | sed "s/^# \{0,1\}//"; exit 0; }

# ---------------------------------------------------------------- helpers
preflight() {
  [ "$(id -u)" = 0 ] || die "run as root: sudo $0 $*"
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] \
    || die "this PoC installs on Ubuntu 24.04 LTS only (found ${PRETTY_NAME:-unknown})"
  ARCH=$(dpkg --print-architecture)
  case $ARCH in amd64 | arm64) ;; *) die "unsupported CPU architecture: $ARCH (amd64 or arm64)" ;; esac
  if [ -f "$ETC/role" ] && [ "$(cat "$ETC/role")" != "$1" ]; then
    die "this machine is already a getarp $(cat "$ETC/role"); one role per machine"
  fi
  touch "$INSTALL_LOG"; chmod 0600 "$INSTALL_LOG"
  exec > >(tee -a "$INSTALL_LOG") 2>&1
  echo "getarp install: $1 on $PRETTY_NAME ($ARCH), $(date -u +%FT%TZ)"
}

apt_install() { apt-get install -y --no-install-recommends "$@"; }

add_apt_repo() { # name key-url "deb line without signed-by"
  local name=$1 key=$2 line=$3
  install -d -m 0755 /etc/apt/keyrings
  if [ ! -s "/etc/apt/keyrings/$name.gpg" ]; then
    curl -fsSL "$key" | gpg --dearmor --yes -o "/etc/apt/keyrings/$name.gpg"
  fi
  echo "deb [signed-by=/etc/apt/keyrings/$name.gpg] $line" > "/etc/apt/sources.list.d/$name.list"
}

sys_user() { # name home [extra useradd args]
  local name=$1 home=$2; shift 2
  getent passwd "$name" >/dev/null && return 0
  local grp=(--user-group)
  getent group "$name" >/dev/null && grp=(-g "$name")
  useradd --system --home-dir "$home" --no-create-home --shell /usr/sbin/nologin "${grp[@]}" "$@" "$name"
}

sys_group() { getent group "$1" >/dev/null || groupadd --system "$1"; }

rand() { openssl rand -hex 24; }

detect_public_ip() {
  curl -fsS -m 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' \
    || curl -fsS -m 10 https://api.ipify.org 2>/dev/null || true
}

detect_route_src() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}'; }

detect_iface() { ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}'; }

caller_ip() { # address of the SSH session running this installer, if any
  local ip=${SSH_CLIENT:-}
  ip=${ip%% *}
  [ -n "$ip" ] || ip=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p')
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$ip" || true
}

valid_cidr_list() { # a.b.c.d[/n][,...]
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?(,[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?)*$ ]]
}

install_ctl() {
  install -m 0755 "$HERE/bin/getarp-ctl" /usr/local/sbin/getarp-ctl
  install -m 0644 "$HERE/common/systemd/getarp-firewall.service" /etc/systemd/system/
  install -d -m 0755 "$OPT/docs"
  install -m 0644 "$HERE/README.md" "$OPT/docs/README.md"
  [ -f "$HERE/docs/USER_GUIDE.md" ] && install -m 0644 "$HERE/docs/USER_GUIDE.md" "$OPT/docs/"
  echo "$HERE" > "$ETC/source-dir"
}

# ================================================================= CORE
core_main() {
  local DOMAIN="" EMAIL="" ADMIN_USER=admin ADMIN_CIDR=""
  local PUBLIC_IP="" BIND_IP="" SSH_PORTS="" BACKUP_S3_URI=""
  while [ $# -gt 0 ]; do
    case $1 in
      --domain) DOMAIN=$2; shift 2 ;;
      --email) EMAIL=$2; shift 2 ;;
      --admin-user) ADMIN_USER=$2; shift 2 ;;
      --admin-cidr) ADMIN_CIDR=$2; shift 2 ;;
      --public-ip) PUBLIC_IP=$2; shift 2 ;;
      --bind-ip) BIND_IP=$2; shift 2 ;;
      --ssh-port) SSH_PORTS=$2; shift 2 ;;
      --backup-s3) BACKUP_S3_URI=$2; shift 2 ;;
      -h | --help) usage ;;
      *) die "unknown option for core: $1" ;;
    esac
  done
  [ -n "$DOMAIN" ] || die "--domain is required (the public name of the dashboard)"
  [ -n "$EMAIL" ] || die "--email is required (for the Let's Encrypt certificate)"
  [[ "$ADMIN_USER" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "--admin-user: letters, digits, . _ - only"
  [[ -z "$BACKUP_S3_URI" || "$BACKUP_S3_URI" == s3://* ]] || die "--backup-s3 must look like s3://bucket/prefix"
  [ -z "$ADMIN_CIDR" ] || valid_cidr_list "$ADMIN_CIDR" || die "--admin-cidr: e.g. 203.0.113.7 or 203.0.113.0/24"
  preflight core

  # ------------------------------------------------------------ packages
  step "Packages (PostgreSQL $PG_MAJOR + TimescaleDB, Caddy, CrowdSec)"
  apt-get update -q
  apt_install ca-certificates curl gnupg openssl nftables python3 python3-venv \
    python3-boto3 logrotate postgresql-common caddy nodejs npm iproute2
  [ -f /etc/apt/sources.list.d/pgdg.list ] || /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
  add_apt_repo timescaledb https://packagecloud.io/timescale/timescaledb/gpgkey \
    "https://packagecloud.io/timescale/timescaledb/ubuntu/ noble main"
  add_apt_repo crowdsec https://packagecloud.io/crowdsec/crowdsec/gpgkey \
    "https://packagecloud.io/crowdsec/crowdsec/ubuntu/ noble main"
  apt-get update -q
  apt_install "postgresql-$PG_MAJOR" "timescaledb-2-postgresql-$PG_MAJOR" timescaledb-tools crowdsec

  # ------------------------------------------------------------ addresses
  step "Addresses and SSH ports"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(detect_public_ip)
  [ -n "$PUBLIC_IP" ] || die "could not detect the public IP; pass --public-ip"
  [ -n "$BIND_IP" ] || BIND_IP=$(detect_route_src)
  [ -n "$BIND_IP" ] || die "could not detect the local address; pass --bind-ip"
  if [ -z "$SSH_PORTS" ]; then
    # Every port sshd is configured for, plus every port an SSH session is
    # connected to right now: the new firewall must never cut you off.
    SSH_PORTS=$( {
      sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
      ss -tnpH state established 2>/dev/null | awk '/"sshd/ {n = split($3, a, ":"); print a[n]}'
    } | sort -un | paste -sd, -)
  fi
  SSH_PORTS=${SSH_PORTS//[[:space:]]/}
  [[ "$SSH_PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "could not work out the SSH port; pass --ssh-port"
  say "public IP $PUBLIC_IP, site listens on $BIND_IP, SSH kept open on ${SSH_PORTS//,/, }"
  if [ -z "$ADMIN_CIDR" ] && ! grep -q '^admin,' "$ETC/peers.csv" 2>/dev/null; then
    ADMIN_CIDR=$(caller_ip)
    if [ -n "$ADMIN_CIDR" ]; then
      say "admin access from $ADMIN_CIDR (the address you are connected from)"
    else
      warn "could not tell your address; allow one later with: getarp-ctl admin add <name> <ip>"
    fi
  fi

  # ------------------------------------------------------------ accounts and folders
  step "Accounts and folders"
  install -d -m 0755 "$ETC" "$ETC/svc" "$OPT"
  echo core > "$ETC/role"
  sys_group getarp-logs
  sys_user getarp-ingest /var/lib/getarp/ingest
  local s
  for s in pipeline enrichment api; do
    sys_user "svc-$s" /nonexistent
  done
  usermod -a -G getarp-logs svc-pipeline
  install -d -m 0755 /var/lib/getarp
  install -d -m 2750 -o getarp-ingest -g getarp-logs /var/lib/getarp/logs
  install -d -m 0755 -o getarp-ingest -g getarp-ingest /var/lib/getarp/ingest
  install -d -m 0700 /var/backups/getarp
  install -d -m 0755 -o caddy -g caddy /var/log/caddy

  # ------------------------------------------------------------ secrets
  step "Secrets (made once, kept in $ETC/secrets.env, root only)"
  if [ ! -s "$ETC/secrets.env" ]; then
    (
      umask 077
      cat > "$ETC/secrets.env" <<EOF
# getarp core secrets. Made by install.sh; keep this file root-only.
PG_PW_PIPELINE=$(rand)
PG_PW_ENRICHMENT=$(rand)
PG_PW_API=$(rand)
SESSION_SECRET=$(rand)$(rand)
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
EOF
    )
    say "new secrets written"
  else
    say "existing secrets kept"
  fi
  # shellcheck disable=SC1091
  . "$ETC/secrets.env"

  # ------------------------------------------------------------ firewall
  step "Firewall and web server config"
  cat > "$ETC/core.env" <<EOF
# getarp core settings. Read by getarp-ctl. Re-run install.sh to change them.
DOMAIN=$DOMAIN
EMAIL=$EMAIL
PUBLIC_IP=$PUBLIC_IP
BIND_IP=$BIND_IP
SSH_PORTS="${SSH_PORTS//,/, }"
PG_MAJOR=$PG_MAJOR
BACKUP_S3_URI=$BACKUP_S3_URI
EOF
  chmod 0644 "$ETC/core.env"
  install_ctl
  printf "vm.overcommit_memory = 1\n" > /etc/sysctl.d/60-getarp.conf
  sysctl -q -p /etc/sysctl.d/60-getarp.conf
  systemctl daemon-reload
  [ -f /etc/caddy/Caddyfile.orig ] || cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.orig 2>/dev/null || true
  getarp-ctl apply >/dev/null
  local cidr n=1
  for cidr in ${ADMIN_CIDR//,/ }; do
    while grep -q "^admin,admin$n," "$ETC/peers.csv"; do n=$((n + 1)); done
    getarp-ctl admin add "admin$n" "$cidr" >/dev/null || warn "could not add admin address $cidr"
  done
  systemctl enable --now getarp-firewall.service
  say "firewall on"

  # ------------------------------------------------------------ database
  step "Database (PostgreSQL $PG_MAJOR + TimescaleDB)"
  local pgconf=/etc/postgresql/$PG_MAJOR/main
  local mem_mb; mem_mb=$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)
  if ! grep -q "^shared_preload_libraries.*timescaledb" "$pgconf/postgresql.conf"; then
    # Give the database about half the memory: the rest of getarp lives here too.
    timescaledb-tune --quiet --yes --pg-config="/usr/lib/postgresql/$PG_MAJOR/bin/pg_config" \
      --conf-path="$pgconf/postgresql.conf" --memory="$((mem_mb / 2))MB" >/dev/null
  fi
  cat > "$pgconf/conf.d/60-getarp.conf" <<'EOF'
# getarp
listen_addresses = 'localhost'
timescaledb.telemetry_level = off
EOF
  systemctl restart "postgresql@$PG_MAJOR-main"
  for _ in $(seq 1 30); do pg_isready -q -h 127.0.0.1 && break; sleep 1; done
  psql_pg() { (cd / && runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"); }
  if [ -z "$(psql_pg -tAc "SELECT 1 FROM pg_database WHERE datname = 'getarp'")" ]; then
    psql_pg -c "CREATE DATABASE getarp"
  fi
  # Schema changes are numbered files in app/migrations; each runs once.
  psql_pg -d getarp -c "CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
  local m name
  for m in "$HERE"/app/migrations/*.sql; do
    name=$(basename "$m")
    if [ -z "$(psql_pg -d getarp -tAc "SELECT 1 FROM schema_migrations WHERE name = '$name'")" ]; then
      { echo "BEGIN;"; cat "$m"; echo "INSERT INTO schema_migrations (name) VALUES ('$name');"
        echo "COMMIT;"; } | psql_pg -d getarp >/dev/null
      say "applied $name"
    fi
  done
  # One login per service, with only the rights it needs.
  psql_pg -d getarp -v pw_pipeline="$PG_PW_PIPELINE" -v pw_enrichment="$PG_PW_ENRICHMENT" \
    -v pw_api="$PG_PW_API" <<'SQL'
SELECT 'CREATE ROLE ' || r || ' LOGIN'
  FROM unnest(ARRAY['svc_pipeline', 'svc_enrichment', 'svc_api']) AS r
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) \gexec
ALTER ROLE svc_pipeline   PASSWORD :'pw_pipeline';
ALTER ROLE svc_enrichment PASSWORD :'pw_enrichment';
ALTER ROLE svc_api        PASSWORD :'pw_api';
REVOKE ALL ON DATABASE getarp FROM PUBLIC;
GRANT CONNECT ON DATABASE getarp TO svc_pipeline, svc_enrichment, svc_api;
GRANT USAGE ON SCHEMA public TO svc_pipeline, svc_enrichment, svc_api;
-- pipeline: writes events and everything derived from them
GRANT SELECT, INSERT, UPDATE, DELETE ON events, ips, ip_hourly, findings, profiles, status TO svc_pipeline;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO svc_pipeline;
-- enrichment: reads and annotates addresses
GRANT SELECT, UPDATE ON ips TO svc_enrichment;
-- api: reads everything, writes nothing
GRANT SELECT ON events, ips, ip_hourly, findings, profiles, status, users TO svc_api;
SQL
  say "service logins ready"

  # ------------------------------------------------------------ application
  step "Application (pipeline, enrichment, API)"
  install -d -m 0755 "$OPT/app" "$OPT/core"
  rm -rf "$OPT/app/getarp"
  cp -a "$HERE/app/getarp" "$HERE/app/migrations" "$HERE/app/requirements.txt" "$OPT/app/"
  chown -R root:root "$OPT/app"
  install -m 0755 "$HERE/core/getarp-ingest.py" "$OPT/core/getarp-ingest.py"
  [ -x "$OPT/venv/bin/python" ] || python3 -m venv "$OPT/venv"
  "$OPT/venv/bin/pip" install -q --disable-pip-version-check -r "$HERE/app/requirements.txt"

  step "Country and network data (DB-IP Lite, free, monthly)"
  install -m 0755 "$HERE/bin/getarp-geoip" /usr/local/sbin/getarp-geoip
  if [ ! -s /var/lib/getarp/geoip/dbip-asn-lite.mmdb ]; then
    getarp-geoip || warn "could not download it now; it retries monthly (run: sudo getarp-geoip)"
  fi

  if [ ! -f "$ETC/app.env" ]; then
    cat > "$ETC/app.env" <<'EOF'
# getarp settings shared by all application services. Not secret.
# Change, then: sudo systemctl restart 'getarp@*'
PG_HOST=127.0.0.1
PG_PORT=5432
PG_DB=getarp
LOG_DIR=/var/lib/getarp/logs
GEOIP_DIR=/var/lib/getarp/geoip
# Detection thresholds
SWEEP_PORTS=4
SWEEP_WINDOW=60
BRUTE_ATTEMPTS=10
BRUTE_WINDOW=120
EOF
  fi
  svc_env() { # name pg-user pg-pw args...
    local name=$1 pgu=$2 pgp=$3; shift 3
    local keep=""
    # keep lines the operator added (e.g. threat-intel keys) below the marker
    [ -f "$ETC/svc/$name.env" ] && keep=$(sed -n '/^# --- your settings/,$p' "$ETC/svc/$name.env" | tail -n +2)
    (
      umask 027
      cat > "$ETC/svc/$name.env" <<EOF
# getarp@$name: its own database login. Written by install.sh.
PG_USER=$pgu
PG_PASSWORD=$pgp
GETARP_ARGS=$*
# --- your settings (kept when install.sh runs again)
$keep
EOF
    )
    chown "root:svc-$name" "$ETC/svc/$name.env"
  }
  svc_env pipeline svc_pipeline "$PG_PW_PIPELINE" -m getarp.pipeline
  svc_env enrichment svc_enrichment "$PG_PW_ENRICHMENT" -m getarp.enrich
  svc_env api svc_api "$PG_PW_API" -m uvicorn getarp.api:app --host 127.0.0.1 --port 8000 \
    --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-server-header --log-level warning
  sed -i "/^PG_PASSWORD=/a SESSION_SECRET=$SESSION_SECRET" "$ETC/svc/api.env"
  if ! grep -q '^#.*CROWDSEC_CTI_KEY' "$ETC/svc/enrichment.env"; then
    printf '%s\n' "# Threat-intel reputation (optional, pick one): CROWDSEC_CTI_KEY=... or ABUSEIPDB_KEY=..." \
      "# REPUTATION_PER_DAY=40" >> "$ETC/svc/enrichment.env"
  fi

  install -m 0644 "$HERE/core/systemd/getarp@.service" "$HERE/core/systemd/getarp-ingest.service" \
    "$HERE/core/systemd/getarp-backup.service" "$HERE/core/systemd/getarp-backup.timer" \
    "$HERE/core/systemd/getarp-geoip.service" "$HERE/core/systemd/getarp-geoip.timer" \
    /etc/systemd/system/
  # Only enrichment talks to the internet (threat-intel lookups).
  for s in pipeline api; do
    install -d -m 0755 "/etc/systemd/system/getarp@$s.service.d"
    printf '[Service]\nIPAddressAllow=localhost\nIPAddressDeny=any\n' \
      > "/etc/systemd/system/getarp@$s.service.d/10-no-internet.conf"
  done
  printf '[Service]\nSupplementaryGroups=getarp-logs\nStateDirectory=getarp/pipeline\nStateDirectoryMode=0750\n' \
    > "/etc/systemd/system/getarp@pipeline.service.d/20-logs-and-state.conf"
  systemctl daemon-reload
  systemctl enable getarp-ingest getarp@pipeline getarp@enrichment getarp@api getarp-geoip.timer
  systemctl restart getarp-ingest getarp@pipeline getarp@enrichment getarp@api

  # First dashboard login, only if there is none yet.
  if [ "$(psql_pg -d getarp -tAc "SELECT count(*) FROM users")" = 0 ]; then
    local hash
    hash=$(printf '%s' "$ADMIN_PASSWORD" | "$OPT/venv/bin/python" -I -c \
      'import sys, bcrypt; print(bcrypt.hashpw(sys.stdin.read().encode(), bcrypt.gensalt()).decode())')
    psql_pg -d getarp -v u="$ADMIN_USER" -v h="$hash" \
      <<<"INSERT INTO users (username, password_hash) VALUES (:'u', :'h');"
    say "first admin login created: $ADMIN_USER"
  fi

  # ------------------------------------------------------------ web
  step "Dashboard (build the frontend, configure Caddy)"
  local build; build=$(mktemp -d)
  cp -a "$HERE/app/frontend/." "$build/"
  rm -rf "$build/node_modules" "$build/dist"
  (cd "$build" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent)
  install -d -m 0755 /var/www/getarp
  rm -rf /var/www/getarp.new && cp -a "$build/dist" /var/www/getarp.new
  rm -rf /var/www/getarp && mv /var/www/getarp.new /var/www/getarp
  rm -rf "$build"
  getarp-ctl apply >/dev/null   # writes and checks the web server config
  systemctl daemon-reload
  systemctl enable caddy
  systemctl restart caddy

  # ------------------------------------------------------------ crowdsec
  step "CrowdSec (bans attackers seen by any sensor, on the core's firewall)"
  install -m 0644 "$HERE/core/crowdsec-acquis.yaml" /etc/crowdsec/acquis.d/getarp.yaml
  install -m 0644 "$HERE/core/crowdsec-profiles.yaml" /etc/crowdsec/profiles.yaml
  cscli hub update >/dev/null || warn "CrowdSec hub update failed"
  cscli parsers install crowdsecurity/cowrie-logs >/dev/null || warn "could not install cowrie-logs"
  for s in crowdsecurity/sshd crowdsecurity/suricata crowdsecurity/caddy \
    crowdsecurity/http-cve crowdsecurity/base-http-scenarios; do
    cscli collections install "$s" >/dev/null || warn "could not install $s"
  done
  getarp-ctl apply >/dev/null   # writes the allowlist of getarp's own addresses
  systemctl enable crowdsec
  systemctl restart crowdsec
  dpkg -s crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
    || apt_install crowdsec-firewall-bouncer-nftables
  systemctl enable --now crowdsec-firewall-bouncer || warn "the CrowdSec bouncer did not start"

  # ------------------------------------------------------------ upkeep
  step "Log rotation and nightly backup"
  install -m 0644 "$HERE/core/logrotate-getarp" /etc/logrotate.d/getarp
  systemctl enable --now getarp-backup.timer
  (umask 077; echo "$ADMIN_USER $ADMIN_PASSWORD" > "$ETC/admin-password")

  # ------------------------------------------------------------ done
  sleep 3
  step "Done"
  getarp-ctl status || true
  cat <<EOF

  Dashboard          https://$DOMAIN   (DNS: $DOMAIN A $PUBLIC_IP)
  First admin        $ADMIN_USER / $ADMIN_PASSWORD
                     (also in $ETC/admin-password; change it: sudo getarp-ctl password $ADMIN_USER)
  Admin sign-in from $(getarp-ctl list | awk '$1=="admin" && $4=="yes" {print $3}' | paste -sd' ' -)
                     (more: sudo getarp-ctl admin add <name> <ip>)

  Open these to the internet in your cloud firewall / security group:
    TCP 80, 443   and your SSH port(s): ${SSH_PORTS//,/, }

  Next: add a sensor:   sudo getarp-ctl sensor add s01 <sensor public ip>
        (it prints the key and the exact install command for the sensor)

  Full guide: $OPT/docs/USER_GUIDE.md      Install log: $INSTALL_LOG
EOF
}

# ================================================================= SENSOR
sensor_main() {
  local CORE_URL="" KEY="" ADMIN_CIDR="" IFACE="" PUBLIC_IP=""
  while [ $# -gt 0 ]; do
    case $1 in
      --core) CORE_URL=${2%/}; shift 2 ;;
      --key) KEY=$2; shift 2 ;;
      --admin-cidr) ADMIN_CIDR=$2; shift 2 ;;
      --iface) IFACE=$2; shift 2 ;;
      --public-ip) PUBLIC_IP=$2; shift 2 ;;
      -h | --help) usage ;;
      *) die "unknown option for sensor: $1" ;;
    esac
  done
  [[ "$CORE_URL" =~ ^https://[A-Za-z0-9.-]+$ ]] || die "--core https://<the core's name> is required"
  [[ "$KEY" =~ ^[0-9a-f]{64}$ ]] \
    || die "--key is required: the key \"getarp-ctl sensor add\" printed on the core"
  [ -z "$ADMIN_CIDR" ] || valid_cidr_list "$ADMIN_CIDR" || die "--admin-cidr: e.g. 203.0.113.7 or 203.0.113.0/24"
  preflight sensor

  # ------------------------------------------------------------ packages
  step "Packages (nftables, Suricata, Python)"
  apt-get update -q
  apt_install ca-certificates curl openssl git nftables python3 python3-venv \
    suricata suricata-update logrotate iproute2

  # ------------------------------------------------------------ addresses
  step "Addresses, and a test delivery to the core"
  [ -n "$IFACE" ] || IFACE=$(detect_iface)
  [ -n "$IFACE" ] && ip link show "$IFACE" >/dev/null 2>&1 || die "could not find the public interface; pass --iface"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(detect_public_ip)
  local host=${CORE_URL#https://} core_ip
  core_ip=$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')
  [ -n "$core_ip" ] || die "cannot resolve $host"
  if [ -z "$ADMIN_CIDR" ]; then
    ADMIN_CIDR=$(caller_ip)
    [ -n "$ADMIN_CIDR" ] || die "could not tell which address you are connected from. Pass
       --admin-cidr <your IP> (who may reach this machine's real SSH from the internet)."
  fi
  # An empty batch: proves the name, the certificate, the key and the address allowlist.
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
    -H "Authorization: Bearer $KEY" --data-binary '' "$CORE_URL/ingest" || true)
  case $code in
    200) say "the core accepts this sensor" ;;
    401) die "the core does not know this key (or the sensor was removed). Run on the core:
       sudo getarp-ctl sensor add <name> ${PUBLIC_IP:-<this sensor public ip>}" ;;
    404) die "the core does not accept deliveries from this address (${PUBLIC_IP:-unknown}). On the core:
       sudo getarp-ctl sensor move <name> ${PUBLIC_IP:-<this sensor public ip>}" ;;
    *) die "cannot reach $CORE_URL/ingest (answer: ${code:-none}); check DNS, its certificate and TCP 443" ;;
  esac
  say "interface $IFACE, public IP ${PUBLIC_IP:-unknown}, core $host ($core_ip), admin SSH from $ADMIN_CIDR"

  # ------------------------------------------------------------ accounts and folders
  step "Accounts and folders"
  install -d -m 0755 "$ETC" "$OPT"
  echo sensor > "$ETC/role"
  sys_group getarp-logs
  sys_user cowrie /var/lib/cowrie
  sys_user hpextra /nonexistent
  sys_user getarp-ship /var/lib/getarp-shipper
  sys_user suricata /var/lib/suricata
  usermod -a -G getarp-logs getarp-ship
  install -d -m 0755 /var/log/getarp
  install -d -m 2750 -o cowrie -g getarp-logs /var/log/getarp/cowrie
  install -d -m 2750 -o hpextra -g getarp-logs /var/log/getarp/extra
  install -d -m 2750 -o suricata -g getarp-logs /var/log/getarp/suricata
  install -d -m 0755 /var/lib/suricata /var/lib/suricata/rules
  cat > "$ETC/sensor.env" <<EOF
# getarp sensor settings. Read by getarp-ctl and systemd. Re-run install.sh to change.
CORE_URL=$CORE_URL
CORE_IP=$core_ip
PUBLIC_IFACE=$IFACE
PUBLIC_IP=$PUBLIC_IP
ADMIN_CIDR=$ADMIN_CIDR
EOF
  chmod 0644 "$ETC/sensor.env"
  (
    umask 027
    printf 'GETARP_CORE_URL=%s\nGETARP_SENSOR_KEY=%s\n' "$CORE_URL" "$KEY" > "$ETC/shipper.env"
  )
  chown root:getarp-ship "$ETC/shipper.env"
  install_ctl

  # ------------------------------------------------------------ cowrie
  step "Cowrie decoy $COWRIE_REF (SSH/Telnet on public 22/23)"
  install -d -m 0755 /opt/cowrie
  if [ ! -d /opt/cowrie/src/.git ]; then
    git clone -q --branch "$COWRIE_REF" --depth 1 "$COWRIE_REPO" /opt/cowrie/src
  fi
  [ "$(git -C /opt/cowrie/src rev-parse HEAD)" = "$COWRIE_COMMIT" ] \
    || die "Cowrie $COWRIE_REF is not the expected commit $COWRIE_COMMIT; stopping"
  [ -x /opt/cowrie/venv/bin/python ] || python3 -m venv /opt/cowrie/venv
  /opt/cowrie/venv/bin/pip install -q --disable-pip-version-check /opt/cowrie/src
  install -d -m 0750 -g cowrie /etc/cowrie
  install -m 0640 -g cowrie "$HERE/sensor/cowrie/cowrie.cfg" /etc/cowrie/cowrie.cfg
  install -m 0640 -g cowrie "$HERE/sensor/cowrie/userdb.txt" /etc/cowrie/userdb.txt
  install -m 0644 "$HERE/sensor/systemd/getarp-cowrie.service" /etc/systemd/system/

  # ------------------------------------------------------------ decoys
  step "Extra decoys (HTTP, MySQL, FTP, Redis)"
  install -d -m 0755 "$OPT/sensor/decoys"
  install -m 0644 "$HERE/sensor/decoys/services.py" "$OPT/sensor/decoys/services.py"
  install -m 0644 "$HERE/sensor/systemd/getarp-decoys.service" /etc/systemd/system/

  # ------------------------------------------------------------ suricata
  step "Suricata IDS on $IFACE"
  systemctl disable --now suricata.service >/dev/null 2>&1 || true
  install -m 0644 "$HERE/sensor/suricata/suricata.yaml" "$ETC/suricata.yaml"
  install -m 0644 "$HERE/sensor/suricata/rules/getarp-local.rules" "$ETC/getarp-local.rules"
  suricata-update --suricata-conf "$ETC/suricata.yaml" --no-reload --quiet \
    || warn "rule download failed; Suricata starts with getarp's own rules and retries daily"
  [ -f /var/lib/suricata/rules/suricata.rules ] || : > /var/lib/suricata/rules/suricata.rules
  install -m 0644 "$HERE/sensor/systemd/getarp-suricata.service" \
    "$HERE/sensor/systemd/getarp-sensor-daily.service" "$HERE/sensor/systemd/getarp-sensor-daily.timer" \
    /etc/systemd/system/

  # ------------------------------------------------------------ shipper
  step "Shipper (sends this sensor's logs to the core)"
  install -d -m 0755 "$OPT/sensor"
  install -m 0755 "$HERE/sensor/getarp-shipper.py" "$OPT/sensor/getarp-shipper.py"
  install -m 0644 "$HERE/sensor/systemd/getarp-shipper.service" /etc/systemd/system/
  install -m 0644 "$HERE/sensor/logrotate-getarp" /etc/logrotate.d/getarp

  # ------------------------------------------------------------ ssh
  step "Real SSH moves to port 2022 (public 22 becomes the decoy)"
  install -d -m 0755 /etc/ssh/sshd_config.d
  echo "Port 2022" > /etc/ssh/sshd_config.d/05-getarp-port.conf
  sshd -t || { rm -f /etc/ssh/sshd_config.d/05-getarp-port.conf; die "sshd rejected the new port; nothing changed"; }
  # Ubuntu 24.04 starts sshd from a socket by default; use the plain service so
  # the port comes from sshd_config. Your current session stays connected.
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true
  systemctl enable ssh.service >/dev/null 2>&1
  systemctl restart ssh.service
  say "sshd now listens on: $(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | paste -sd' ' -)"

  # ------------------------------------------------------------ firewall and start
  step "Firewall and services"
  systemctl daemon-reload
  getarp-ctl apply
  systemctl enable --now getarp-firewall.service
  local u
  for u in getarp-cowrie getarp-decoys getarp-suricata getarp-shipper; do
    systemctl enable "$u" >/dev/null 2>&1
    systemctl restart "$u"
  done
  systemctl enable --now getarp-sensor-daily.timer

  sleep 3
  step "Done"
  getarp-ctl status || true
  cat <<EOF

  This sensor delivers to $CORE_URL. Attacks show on the dashboard within a
  minute of the first scanner finding it ("sudo getarp-ctl status" on the core).

  Open these to the internet in your cloud firewall / security group:
    TCP 21, 22, 23, 80, 2222, 2223, 8080, 8081, 2121, 3306, 6379   (the decoys)
    TCP 2022 from ${ADMIN_CIDR//,/, } only                          (your real SSH)
  From now on, log in with:  ssh -p 2022 <user>@${PUBLIC_IP:-<sensor ip>}

  Full guide: $OPT/docs/USER_GUIDE.md      Install log: $INSTALL_LOG
EOF
}

# ================================================================= main
case ${1:-} in
  core) shift; core_main "$@" ;;
  sensor) shift; sensor_main "$@" ;;
  -h | --help | help | "") usage ;;
  *) die "first argument must be 'core' or 'sensor' (try: $0 --help)" ;;
esac
