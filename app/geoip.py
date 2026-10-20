"""
IP -> country lookup. Deterministic mock, derived from a hash of the IP
itself (same approach Mongoose uses for its enrichment mock): the same
IP always resolves to the same country, across runs, so impossible-travel
detection is reproducible without a live geo-IP API or key.
"""

import hashlib

_COUNTRIES = ["IN", "US", "GB", "DE", "SG", "RU", "BR", "AU", "JP", "ZA"]


def country_for_ip(ip: str) -> str:
    digest = hashlib.sha256(ip.encode()).hexdigest()
    return _COUNTRIES[int(digest[:8], 16) % len(_COUNTRIES)]
