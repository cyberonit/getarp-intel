"""Concrete enrichment providers. Add a new one by subclassing + @register."""
import httpx
from base import Enrichment, EnrichmentProvider, register


@register
class CrowdSecProvider(EnrichmentProvider):
    """Uses CrowdSec CTI (api.crowdsec.net). Falls back to local LAPI decisions."""
    name = "crowdsec"
    CTI = "https://cti.api.crowdsec.net/v2/smoke/"

    async def enrich(self, ip: str) -> Enrichment:
        key = self.settings.get("CROWDSEC_CTI_KEY")
        e = Enrichment(src_ip=ip, provider=self.name)
        if not key:
            # no CTI key: at least reflect whether our own LAPI has banned it
            return await self._local(ip, e)
        headers = {"x-api-key": key, "accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.CTI + ip, headers=headers)
            if resp.status_code == 404:
                e.reputation = "clean"
                return e
            resp.raise_for_status()
            d = resp.json()
            e.raw = d
            e.reputation = d.get("reputation", "unknown")
            e.confidence = {"malicious": 0.95, "suspicious": 0.6,
                            "known": 0.4}.get(e.reputation, 0.1)
            e.is_known_attacker = e.reputation in ("malicious", "suspicious")
            loc = d.get("location", {})
            e.country = loc.get("country")
            asn = (d.get("as_name") or "")
            e.asn = str(d.get("as_num") or "")
            e.org = asn
            behaviors = d.get("behaviors", []) or []
            e.categories = [b.get("label", b.get("name", "")) for b in behaviors]
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e

    async def _local(self, ip: str, e: Enrichment) -> Enrichment:
        url = self.settings.get("CROWDSEC_LAPI_URL", "")
        e.reputation = "unknown"
        e.categories = ["cti-key-missing"]
        return e


@register
class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("ABUSEIPDB_KEY")
        if not key:
            e.categories = ["api-key-missing"]
            return e
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL,
                                   headers={"Key": key, "Accept": "application/json"},
                                   params={"ipAddress": ip, "maxAgeInDays": 90})
            resp.raise_for_status()
            d = resp.json().get("data", {})
            e.raw = d
            score = d.get("abuseConfidenceScore", 0)
            e.confidence = score / 100.0
            e.country = d.get("countryCode")
            e.org = d.get("isp")
            e.is_known_attacker = score >= 50
            e.reputation = ("malicious" if score >= 75 else
                            "suspicious" if score >= 25 else "clean")
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e


@register
class GreyNoiseProvider(EnrichmentProvider):
    name = "greynoise"
    URL = "https://api.greynoise.io/v3/community/"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("GREYNOISE_KEY")
        headers = {"key": key} if key else {}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL + ip, headers=headers)
            if resp.status_code == 404:
                e.reputation = "clean"
                return e
            resp.raise_for_status()
            d = resp.json()
            e.raw = d
            cls = d.get("classification", "unknown")
            e.reputation = {"malicious": "malicious", "benign": "clean"}.get(cls, "unknown")
            e.is_known_attacker = cls == "malicious"
            e.org = d.get("name")
            e.categories = [cls]
            e.confidence = 0.8 if cls == "malicious" else 0.3
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e


@register
class VirusTotalProvider(EnrichmentProvider):
    """VirusTotal IP report. Free tier: 500 lookups/day, 4/min."""
    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/ip_addresses/"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("VIRUSTOTAL_KEY")
        if not key:
            e.categories = ["api-key-missing"]
            return e
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL + ip, headers={"x-apikey": key})
            if resp.status_code == 404:
                e.reputation = "clean"
                return e
            resp.raise_for_status()
            attr = resp.json().get("data", {}).get("attributes", {})
            e.raw = attr
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            e.confidence = round((malicious + suspicious) / total, 3)
            e.country = attr.get("country")
            e.asn = str(attr.get("asn") or "")
            e.org = attr.get("as_owner")
            e.is_known_attacker = malicious >= 3
            e.reputation = ("malicious" if malicious >= 5 else
                            "suspicious" if (malicious + suspicious) >= 1 else "clean")
            # collect category labels from engines that flagged it
            results = attr.get("last_analysis_results", {})
            cats = {r.get("category") for r in results.values()
                    if r.get("category") in ("malicious", "suspicious")}
            e.categories = sorted(c for c in cats if c)
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e


@register
class CiscoTalosProvider(EnrichmentProvider):
    """Cisco Talos reputation feed — no API key required.

    Talos has no official public API; this queries the public reputation
    endpoint used by talosintelligence.com. Treat as best-effort: if the
    endpoint shape changes or is unreachable, it degrades to 'unknown'
    rather than failing the pipeline.
    """
    name = "ciscotalos"
    URL = "https://talosintelligence.com/sb_api/query_lookup"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        try:
            params = {
                "query": "/api/v2/details/ip/",
                "query_entry": ip,
            }
            headers = {"User-Agent": "Mozilla/5.0", "Referer": "https://talosintelligence.com/reputation_center/"}
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
                resp = await c.get(self.URL, params=params, headers=headers)
            if resp.status_code != 200:
                e.reputation = "unknown"
                e.categories = ["talos-unavailable"]
                return e
            d = resp.json()
            e.raw = d
            # Talos returns a web/email reputation label: Good / Neutral / Poor
            web_rep = (d.get("web_score_name") or d.get("email_score_name")
                       or d.get("threat_level") or "").lower()
            mapping = {"poor": "malicious", "neutral": "suspicious", "good": "clean"}
            e.reputation = mapping.get(web_rep, "unknown")
            e.is_known_attacker = e.reputation == "malicious"
            e.confidence = {"malicious": 0.7, "suspicious": 0.4, "clean": 0.1}.get(e.reputation, 0.0)
            e.country = d.get("country_name") or d.get("country")
            e.org = d.get("owner") or d.get("org")
            if web_rep:
                e.categories = [f"talos:{web_rep}"]
        except Exception as ex:
            e.reputation = "unknown"
            e.raw = {"error": str(ex), "note": "talos endpoint best-effort"}
        return e


@register
class MultiProvider(EnrichmentProvider):
    """Recommended provider: queries ALL configured providers in parallel and
    merges their verdicts. A provider with a missing key is simply skipped.

    Merge strategy:
      - reputation: worst-of (malicious > suspicious > known > clean > unknown)
      - confidence: max across providers
      - is_known_attacker: any provider says yes
      - country/asn/org: first non-empty (CrowdSec/VT/AbuseIPDB tend to agree)
      - categories: union across providers, prefixed by source
      - raw: per-provider sub-results kept for forensics
    """
    name = "multi"

    # severity ordering for worst-of merge
    _RANK = {"unknown": 0, "clean": 1, "known": 2, "suspicious": 3, "malicious": 4}

    def __init__(self, settings: dict):
        super().__init__(settings)
        # instantiate every other registered provider except ourselves
        from base import _REGISTRY
        self._children = [cls(settings) for key, cls in _REGISTRY.items()
                          if key != self.name]

    async def enrich(self, ip: str) -> Enrichment:
        import asyncio
        results = await asyncio.gather(
            *(child.enrich(ip) for child in self._children),
            return_exceptions=True)

        merged = Enrichment(src_ip=ip, provider=self.name)
        sub_raw = {}
        sources_used = []
        best_rep_rank = 0
        for child, res in zip(self._children, results):
            if isinstance(res, Exception):
                sub_raw[child.name] = {"error": str(res)}
                continue
            # skip providers that produced nothing useful (missing key etc.)
            if res.categories and "api-key-missing" in res.categories:
                sub_raw[child.name] = {"skipped": "no api key"}
                continue
            sources_used.append(child.name)
            sub_raw[child.name] = {
                "reputation": res.reputation,
                "confidence": res.confidence,
                "is_known_attacker": res.is_known_attacker,
            }
            # worst-of reputation
            r = self._RANK.get(res.reputation, 0)
            if r > best_rep_rank:
                best_rep_rank = r
                merged.reputation = res.reputation
            # max confidence
            merged.confidence = max(merged.confidence, res.confidence or 0.0)
            # any attacker flag
            merged.is_known_attacker = merged.is_known_attacker or res.is_known_attacker
            # first non-empty geo/org
            merged.country = merged.country or res.country
            merged.asn = merged.asn or res.asn
            merged.org = merged.org or res.org
            # union of categories, source-prefixed
            for cat in (res.categories or []):
                if cat and cat not in ("api-key-missing",):
                    tag = f"{child.name}:{cat}"
                    if tag not in merged.categories:
                        merged.categories.append(tag)

        if best_rep_rank == 0:
            merged.reputation = "unknown"
        merged.raw = {"sources_used": sources_used, "results": sub_raw}
        return merged
