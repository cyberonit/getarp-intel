"""getarp API: read-only data for the dashboard, plus log-in for the admin site.

The public site (Caddy) forwards only the public routes; everything marked
"admin" also needs a signed session cookie. Public answers are cached for a
few seconds, so the database load does not grow with the number of viewers.
One database connection listens for live updates and fans them out to every
connected browser.

Run: uvicorn getarp.api:app
"""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import timedelta

import asyncpg
import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from . import __version__, config

log = logging.getLogger("getarp.api")
LIVE_CHANNEL = "getarp_live"
COOKIE = "getarp_session"
WINDOWS = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7),
           "30d": timedelta(days=30)}
MAX_SOCKETS = 500


# ---------------------------------------------------------------- database
async def _init(con):
    await con.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


class State:
    pool: asyncpg.Pool | None = None
    hub: "Hub | None" = None


S = State()


async def rows(sql, *args):
    async with S.pool.acquire() as con:
        return [dict(r) for r in await con.fetch(sql, *args)]


async def row(sql, *args):
    async with S.pool.acquire() as con:
        r = await con.fetchrow(sql, *args)
        return dict(r) if r else None


_cache: dict = {}


async def cached(key, seconds, make):
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and hit[0] > now:
        return hit[1]
    value = await make()
    _cache[key] = (now + seconds, value)
    if len(_cache) > 512:
        for k in [k for k, (exp, _) in _cache.items() if exp <= now]:
            _cache.pop(k, None)
    return value


# ---------------------------------------------------------------- live updates
class Hub:
    """One LISTEN connection; every browser gets its own small queue."""

    def __init__(self):
        self.queues: set[asyncio.Queue] = set()
        self.con = None
        self.task = None

    def _on_notify(self, _con, _pid, _channel, payload):
        for q in list(self.queues):
            if q.full():
                q.get_nowait()          # slow browser: drop its oldest message
            q.put_nowait(payload)

    async def _keep_listening(self):
        while True:
            try:
                if self.con is None or self.con.is_closed():
                    self.con = await asyncpg.connect(config.PG_DSN)
                    await self.con.add_listener(LIVE_CHANNEL, self._on_notify)
                    log.info("listening for live updates")
            except (OSError, asyncpg.PostgresError) as e:
                log.warning("live updates unavailable: %s", e)
                self.con = None
            await asyncio.sleep(10)

    def start(self):
        self.task = asyncio.create_task(self._keep_listening())

    async def stop(self):
        if self.task:
            self.task.cancel()
        if self.con and not self.con.is_closed():
            await self.con.close()


@asynccontextmanager
async def lifespan(_app):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    S.pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=8, init=_init)
    S.hub = Hub()
    S.hub.start()
    yield
    await S.hub.stop()
    await S.pool.close()


app = FastAPI(title="getarp", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- sessions
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _secret() -> bytes:
    if not config.SESSION_SECRET:
        raise HTTPException(503, "log-in is not configured")
    return config.SESSION_SECRET.encode()


def make_token(user: str) -> str:
    body = _b64(json.dumps({"u": user, "exp": int(time.time()) + config.SESSION_HOURS * 3600}).encode())
    sig = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_token(token: str | None) -> str | None:
    if not token or "." not in token or not config.SESSION_SECRET:
        return None
    body, sig = token.rsplit(".", 1)
    good = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, good):
        return None
    try:
        data = json.loads(_unb64(body))
    except ValueError:
        return None
    return data.get("u") if data.get("exp", 0) > time.time() else None


def admin(request: Request) -> str:
    user = read_token(request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "log in first")
    return user


_DUMMY_HASH = bcrypt.hashpw(b"getarp", bcrypt.gensalt(rounds=12))
_failures: dict[str, list[float]] = {}


def _throttled(client: str) -> bool:
    now = time.time()
    recent = [t for t in _failures.get(client, []) if now - t < 600]
    _failures[client] = recent
    return len(recent) >= 5


@app.post("/api/auth/login")
async def login(request: Request, response: Response):
    client = request.client.host if request.client else "?"
    if _throttled(client):
        raise HTTPException(429, "too many failed log-ins; wait 10 minutes")
    try:
        form = await request.json()
    except ValueError:
        form = None
    if not isinstance(form, dict):
        raise HTTPException(400, "send JSON: {\"username\": ..., \"password\": ...}")
    user, password = str(form.get("username", ""))[:64], str(form.get("password", ""))[:256]
    r = await row("SELECT password_hash FROM users WHERE username = $1", user)
    stored = r["password_hash"].encode() if r else _DUMMY_HASH
    ok = await asyncio.to_thread(bcrypt.checkpw, password.encode(), stored)
    if not (r and ok):
        _failures.setdefault(client, []).append(time.time())
        raise HTTPException(401, "wrong user name or password")
    _failures.pop(client, None)
    response.set_cookie(COOKIE, make_token(user), max_age=config.SESSION_HOURS * 3600,
                        httponly=True, secure=True, samesite="strict", path="/api")
    return {"user": user}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE, path="/api")
    return {"ok": True}


@app.get("/api/me")
async def me(user: str = Depends(admin)):
    return {"user": user}


# ---------------------------------------------------------------- public data
def window(value: str) -> timedelta:
    if value not in WINDOWS:
        raise HTTPException(400, f"window must be one of {', '.join(WINDOWS)}")
    return WINDOWS[value]


@app.get("/api/health")
async def health():
    async with S.pool.acquire() as con:
        await con.fetchval("SELECT 1")
    return {"status": "ok", "version": __version__}


@app.get("/api/status")
async def status():
    async def make():
        snap = await row("SELECT ts, data FROM status ORDER BY ts DESC LIMIT 1")
        recent = await rows("""
            SELECT ts, host(src_ip) AS ip, kind, type, service, severity, sensor
            FROM findings ORDER BY ts DESC LIMIT 15""")
        out = dict(snap["data"]) if snap else {}
        out["updated"] = snap["ts"].isoformat() if snap else None
        out["recent"] = recent
        return out
    return await cached("status", 10, make)


@app.get("/api/ips")
async def ips(order: str = "score", limit: int = Query(50, ge=1, le=200)):
    col = {"score": "score DESC, last_seen DESC", "last_seen": "last_seen DESC",
           "events": "events DESC"}.get(order)
    if not col:
        raise HTTPException(400, "order must be score, last_seen or events")
    return await cached(("ips", order, limit), 15, lambda: rows(f"""
        SELECT host(src_ip) AS ip, score, class, country, asn, as_org,
               cardinality(services) AS services, events, last_seen, reputation
        FROM ips ORDER BY {col} LIMIT $1""", limit))


@app.get("/api/top-countries")
async def top_countries(w: str = Query("1h", alias="window")):
    span = window(w)
    return await cached(("countries", w), 30, lambda: rows("""
        SELECT i.country, count(DISTINCT h.src_ip) AS ips, sum(h.events)::bigint AS events
        FROM ip_hourly h JOIN ips i ON i.src_ip = h.src_ip
        WHERE h.bucket >= date_trunc('hour', now() - $1::interval) AND i.country IS NOT NULL
        GROUP BY i.country ORDER BY ips DESC, events DESC LIMIT 12""", span))


@app.get("/api/top-as")
async def top_as(w: str = Query("1h", alias="window")):
    span = window(w)
    return await cached(("as", w), 30, lambda: rows("""
        SELECT i.asn, max(i.as_org) AS org, count(DISTINCT h.src_ip) AS ips,
               sum(h.events)::bigint AS events
        FROM ip_hourly h JOIN ips i ON i.src_ip = h.src_ip
        WHERE h.bucket >= date_trunc('hour', now() - $1::interval) AND i.asn IS NOT NULL
        GROUP BY i.asn ORDER BY events DESC LIMIT 12""", span))


@app.get("/api/findings")
async def findings(kind: str = "attack", w: str = Query("24h", alias="window"),
                   limit: int = Query(200, ge=1, le=500)):
    if kind not in ("scan", "attack"):
        raise HTTPException(400, "kind must be scan or attack")
    span = window(w)
    return await cached(("findings", kind, w, limit), 15, lambda: rows("""
        SELECT f.ts, host(f.src_ip) AS ip, f.type, f.service, f.severity, f.sensor, f.detail,
               i.country, i.as_org
        FROM findings f LEFT JOIN ips i ON i.src_ip = f.src_ip
        WHERE f.kind = $1 AND f.ts > now() - $2::interval
        ORDER BY f.ts DESC LIMIT $3""", kind, span, limit))


@app.get("/api/behavior")
async def behavior(w: str = Query("24h", alias="window"), limit: int = Query(100, ge=1, le=500)):
    span = window(w)
    return await cached(("behavior", w, limit), 15, lambda: rows("""
        SELECT host(p.src_ip) AS ip, i.score, i.class, i.country, p.sessions,
               cardinality(p.commands) AS commands, p.tooling, p.tactics, p.updated_at
        FROM profiles p JOIN ips i ON i.src_ip = p.src_ip
        WHERE p.updated_at > now() - $1::interval
        ORDER BY i.score DESC, p.updated_at DESC LIMIT $2""", span, limit))


# ---------------------------------------------------------------- admin data
@app.get("/api/ips/{ip}")
async def ip_detail(ip: str, _user: str = Depends(admin)):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "not an IP address") from None
    info = await row("""
        SELECT host(src_ip) AS ip, first_seen, last_seen, events, services, ports, sensors,
               score, class, country, asn, as_org, reputation, rep_checked_at
        FROM ips WHERE src_ip = $1""", addr)
    if not info:
        raise HTTPException(404, "never seen")
    return {
        "info": info,
        "profile": await row("SELECT sessions, commands, tooling, tactics, updated_at "
                             "FROM profiles WHERE src_ip = $1", addr),
        "findings": await rows("SELECT ts, kind, type, service, severity, sensor, detail "
                               "FROM findings WHERE src_ip = $1 ORDER BY ts DESC LIMIT 50", addr),
        "events": await rows("""
            SELECT ts, sensor, source, service, event_type, dst_port, username, password,
                   command, signature
            FROM events WHERE src_ip = $1 ORDER BY ts DESC LIMIT 100""", addr),
    }


# ---------------------------------------------------------------- live
@app.websocket("/api/ws")
async def live(ws: WebSocket):
    if len(S.hub.queues) >= MAX_SOCKETS:
        await ws.close(code=1013)
        return
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    S.hub.queues.add(q)

    async def drain_client():
        while True:
            await ws.receive_text()      # we ignore what the browser sends; this notices it leaving

    reader = asyncio.create_task(drain_client())
    try:
        while not reader.done():
            try:
                msg = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                msg = '{"type":"ping"}'
            await ws.send_text(msg)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        reader.cancel()
        S.hub.queues.discard(q)


@app.exception_handler(asyncpg.PostgresError)
async def db_error(_request, exc):
    log.error("database: %s", exc)
    return JSONResponse({"detail": "database unavailable"}, status_code=503)
