-- getarp schema, version 1.
-- Applied once by install.sh (as postgres) in its own transaction.
-- Works on plain PostgreSQL; with TimescaleDB (installed by install.sh) the
-- time-series tables become hypertables with compression and retention.

-- Every normalised event from every sensor.
CREATE TABLE events (
    ts          timestamptz NOT NULL,
    sensor      text        NOT NULL,          -- sensor name, from its delivery key
    source      text        NOT NULL,          -- cowrie | suricata | extra
    service     text,                          -- ssh, telnet, http, mysql, ftp, redis, ...
    event_type  text        NOT NULL,          -- connect, login_failed, login_success, command,
                                               -- download, request, alert, anomaly
    src_ip      inet        NOT NULL,
    src_port    integer,
    dst_port    integer,                       -- the port the attacker aimed at
    username    text,
    password    text,
    command     text,
    signature   text,
    severity    smallint,
    session     text,
    raw         jsonb
);
CREATE INDEX events_ts_idx  ON events (ts DESC);
CREATE INDEX events_src_idx ON events (src_ip, ts DESC);

-- One row per attacking address: the "tracked hosts".
CREATE TABLE ips (
    src_ip          inet PRIMARY KEY,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    events          bigint      NOT NULL DEFAULT 0,
    services        text[]      NOT NULL DEFAULT '{}',
    ports           integer[]   NOT NULL DEFAULT '{}',
    sensors         text[]      NOT NULL DEFAULT '{}',
    score           real        NOT NULL DEFAULT 0,          -- 0..100, only ever goes up
    class           text        NOT NULL DEFAULT 'prober',   -- prober < scanner < bruteforcer < intruder < exploiter
    country         text,                                    -- ISO code
    asn             integer,
    as_org          text,
    reputation      text,                                    -- from an optional threat-intel provider
    rep_checked_at  timestamptz
);
CREATE INDEX ips_score_idx      ON ips (score DESC);
CREATE INDEX ips_last_seen_idx  ON ips (last_seen DESC);
CREATE INDEX ips_first_seen_idx ON ips (first_seen DESC);
CREATE INDEX ips_rep_todo_idx   ON ips (score DESC) WHERE rep_checked_at IS NULL;

-- Events per address per hour: feeds "top countries / top AS" for any window.
CREATE TABLE ip_hourly (
    bucket  timestamptz NOT NULL,
    src_ip  inet        NOT NULL,
    events  integer     NOT NULL,
    PRIMARY KEY (bucket, src_ip)
);

-- Correlated findings: scans and attacks.
CREATE TABLE findings (
    ts        timestamptz NOT NULL DEFAULT now(),
    id        bigserial,
    src_ip    inet        NOT NULL,
    kind      text        NOT NULL,                 -- scan | attack
    type      text        NOT NULL,                 -- service_sweep, bruteforce, credential_stuffing,
                                                    -- command_exec, malware_download, ids_alert
    service   text,
    severity  smallint    NOT NULL DEFAULT 1,       -- 1 low .. 4 critical
    sensor    text,
    detail    jsonb,
    PRIMARY KEY (ts, id)
);
CREATE INDEX findings_kind_idx ON findings (kind, ts DESC);
CREATE INDEX findings_src_idx  ON findings (src_ip, ts DESC);

-- What an address did after getting in.
CREATE TABLE profiles (
    src_ip      inet PRIMARY KEY REFERENCES ips (src_ip) ON DELETE CASCADE,
    sessions    integer     NOT NULL DEFAULT 0,
    commands    text[]      NOT NULL DEFAULT '{}',   -- distinct, capped at 50
    tooling     text[]      NOT NULL DEFAULT '{}',
    tactics     text[]      NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- The live picture, written every minute by the pipeline.
CREATE TABLE status (
    ts    timestamptz NOT NULL PRIMARY KEY,
    data  jsonb       NOT NULL
);

-- Admin-site logins (set with: getarp-ctl password <user>).
CREATE TABLE users (
    username       text PRIMARY KEY,
    password_hash  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;
        PERFORM create_hypertable('events', 'ts', chunk_time_interval => interval '1 day');
        PERFORM create_hypertable('ip_hourly', 'bucket', chunk_time_interval => interval '7 days');
        PERFORM create_hypertable('findings', 'ts', chunk_time_interval => interval '7 days');
        PERFORM create_hypertable('status', 'ts', chunk_time_interval => interval '30 days');
        ALTER TABLE events SET (timescaledb.compress,
                                timescaledb.compress_segmentby = 'sensor',
                                timescaledb.compress_orderby = 'ts DESC');
        PERFORM add_compression_policy('events', interval '7 days');
        PERFORM add_retention_policy('events', interval '90 days');
        PERFORM add_retention_policy('ip_hourly', interval '90 days');
        PERFORM add_retention_policy('findings', interval '180 days');
        PERFORM add_retention_policy('status', interval '30 days');
    END IF;
END
$$;
