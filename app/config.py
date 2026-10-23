"""Env-driven config. Live geo-IP is opt-in, not default, so the test
suite and the sample-log demo stay offline and deterministic."""

import os

LIVE_GEOIP = os.getenv("MEERKAT_LIVE_GEOIP") == "1"
