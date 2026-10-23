"""
IP -> country lookup, with two modes:

- mock (default): deterministic, derived from a hash of the IP itself
  (same approach Mongoose uses for its enrichment mock) — the same IP
  always resolves to the same country, across runs, so impossible-travel
  detection is reproducible in tests and the sample-log demo without any
  network call.
- live (opt-in via MEERKAT_LIVE_GEOIP=1): queries ip-api.com's free,
  keyless endpoint via the stdlib's urllib, so this stays a
  zero-third-party-dependency project even with live lookups on.
  Falls back to the mock on any network/parse error, since a geo-IP
  miss should degrade the rule, not crash the pipeline.
"""

import hashlib
import json
import logging
import urllib.request

from app.config import LIVE_GEOIP

logger = logging.getLogger("meerkat.geoip")

_COUNTRIES = ["IN", "US", "GB", "DE", "SG", "RU", "BR", "AU", "JP", "ZA"]


def _mock_country_for_ip(ip: str) -> str:
    digest = hashlib.sha256(ip.encode()).hexdigest()
    return _COUNTRIES[int(digest[:8], 16) % len(_COUNTRIES)]


def _live_country_for_ip(ip: str) -> str:
    url = f"http://ip-api.com/json/{ip}?fields=countryCode"
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read().decode())
    code = data.get("countryCode")
    if not code:
        raise ValueError(f"ip-api.com returned no countryCode for {ip}: {data}")
    return code


def country_for_ip(ip: str) -> str:
    if not LIVE_GEOIP:
        return _mock_country_for_ip(ip)
    try:
        return _live_country_for_ip(ip)
    except Exception as exc:
        logger.warning("live geo-IP lookup failed for %s (%s), falling back to mock", ip, exc)
        return _mock_country_for_ip(ip)
