"""Settings from the environment (systemd EnvironmentFile). Nothing secret has a default."""
import os


def env(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def env_int(name, default):
    return int(env(name, default))


PG_DSN = "postgresql://{u}:{p}@{h}:{port}/{db}".format(
    u=env("PG_USER", ""), p=env("PG_PASSWORD", ""), h=env("PG_HOST", "127.0.0.1"),
    port=env("PG_PORT", "5432"), db=env("PG_DB", "getarp"))

LOG_DIR = env("LOG_DIR", "/var/lib/getarp/logs")          # written by getarp-ingest
STATE_DIR = env("STATE_DIRECTORY", "/var/lib/getarp/pipeline")  # set by systemd
GEOIP_DIR = env("GEOIP_DIR", "/var/lib/getarp/geoip")

# Detection thresholds
SWEEP_PORTS = env_int("SWEEP_PORTS", 4)          # distinct ports ...
SWEEP_WINDOW = env_int("SWEEP_WINDOW", 60)       # ... within this many seconds
BRUTE_ATTEMPTS = env_int("BRUTE_ATTEMPTS", 10)   # failed logins ...
BRUTE_WINDOW = env_int("BRUTE_WINDOW", 120)      # ... within this many seconds

# Optional threat-intel providers (reputation). Without a key, enrichment idles.
CROWDSEC_CTI_KEY = env("CROWDSEC_CTI_KEY")
ABUSEIPDB_KEY = env("ABUSEIPDB_KEY")
REPUTATION_PER_DAY = env_int("REPUTATION_PER_DAY", 40)

SESSION_SECRET = env("SESSION_SECRET")
SESSION_HOURS = env_int("SESSION_HOURS", 8)
