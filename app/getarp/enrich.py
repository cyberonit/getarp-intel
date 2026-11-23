"""getarp enrichment: reputation of attacking addresses from a threat-intel service.

Optional. Country and network come from the offline DB-IP data in the
pipeline; this adds "is this address known as malicious elsewhere?".
Set CROWDSEC_CTI_KEY or ABUSEIPDB_KEY in /etc/getarp/svc/enrichment.env to
turn it on. Free tiers allow few lookups, so it spends them on the
highest-scoring addresses first, at most REPUTATION_PER_DAY a day.

Run: python -m getarp.enrich
"""
import asyncio
import logging

import asyncpg
import httpx

from . import config

log = logging.getLogger("getarp.enrich")

TODO_SQL = """
SELECT src_ip FROM ips WHERE rep_checked_at IS NULL
ORDER BY score DESC, last_seen DESC LIMIT 1
"""
SAVE_SQL = """
UPDATE ips SET reputation = $2, rep_checked_at = now(),
               score = CASE WHEN $2 = 'malicious' THEN GREATEST(score, 60) ELSE score END
WHERE src_ip = $1
"""


async def crowdsec(client, ip):
    r = await client.get(f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
                         headers={"x-api-key": config.CROWDSEC_CTI_KEY})
    if r.status_code == 404:
        return "unknown"
    r.raise_for_status()
    return r.json().get("reputation") or "unknown"   # malicious | suspicious | known | safe | unknown


async def abuseipdb(client, ip):
    r = await client.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": str(ip), "maxAgeInDays": 90},
                         headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"})
    r.raise_for_status()
    score = (r.json().get("data") or {}).get("abuseConfidenceScore", 0)
    return "malicious" if score >= 75 else "suspicious" if score >= 25 else "unknown"


async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    provider = crowdsec if config.CROWDSEC_CTI_KEY else abuseipdb if config.ABUSEIPDB_KEY else None
    if provider is None:
        log.info("no threat-intel key set (CROWDSEC_CTI_KEY or ABUSEIPDB_KEY); nothing to do")
        while True:
            await asyncio.sleep(86400)
    pause = 86400 / max(config.REPUTATION_PER_DAY, 1)
    log.info("reputation from %s, up to %d lookups a day", provider.__name__, config.REPUTATION_PER_DAY)
    pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=1)
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            ip = await pool.fetchval(TODO_SQL)
            if ip is None:
                await asyncio.sleep(60)
                continue
            try:
                rep = await provider(client, ip)
                await pool.execute(SAVE_SQL, ip, rep)
                log.info("%s: %s", ip, rep)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    log.warning("provider quota reached; waiting an hour")
                    await asyncio.sleep(3600)
                    continue
                log.warning("%s: provider said %s; skipping it", ip, e.response.status_code)
                await pool.execute(SAVE_SQL, ip, "unknown")
            except (httpx.HTTPError, ValueError) as e:
                log.warning("%s: lookup failed (%s); retrying later", ip, e)
                await asyncio.sleep(60)
                continue
            await asyncio.sleep(pause)


if __name__ == "__main__":
    asyncio.run(main())
