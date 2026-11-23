"""Country and network (AS) of an address, from the free DB-IP Lite databases.

Offline, no API key, no rate limit. The files are fetched monthly by
getarp-geoip into GEOIP_DIR; this module notices new files by itself.
IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.
"""
import logging
import os
import time

import maxminddb

from . import config

log = logging.getLogger("getarp.geo")
FILES = {"country": "dbip-country-lite.mmdb", "asn": "dbip-asn-lite.mmdb"}


class Geo:
    def __init__(self, directory=None):
        self.dir = directory or config.GEOIP_DIR
        self.readers = {}
        self.mtimes = {}
        self.checked = 0.0
        self._refresh(force=True)

    def _refresh(self, force=False):
        if not force and time.monotonic() - self.checked < 600:
            return
        self.checked = time.monotonic()
        for kind, name in FILES.items():
            path = os.path.join(self.dir, name)
            try:
                mtime = os.stat(path).st_mtime
            except FileNotFoundError:
                continue
            if self.mtimes.get(kind) == mtime:
                continue
            try:
                reader = maxminddb.open_database(path, maxminddb.MODE_MEMORY)
            except (OSError, ValueError) as e:
                log.warning("cannot open %s: %s", path, e)
                continue
            old = self.readers.get(kind)
            self.readers[kind], self.mtimes[kind] = reader, mtime
            if old:
                old.close()
            log.info("loaded %s", name)

    def lookup(self, ip):
        """(country, asn, as_org); None for anything unknown."""
        self._refresh()
        country = asn = org = None
        reader = self.readers.get("country")
        if reader:
            rec = reader.get(str(ip)) or {}
            country = (rec.get("country") or {}).get("iso_code")
        reader = self.readers.get("asn")
        if reader:
            rec = reader.get(str(ip)) or {}
            asn = rec.get("autonomous_system_number")
            org = rec.get("autonomous_system_organization")
        return country, asn, org
