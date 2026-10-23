import app.geoip as geoip


def test_mock_is_deterministic():
    assert geoip.country_for_ip("1.2.3.4") == geoip.country_for_ip("1.2.3.4")


def test_mock_default_mode_does_not_hit_network(monkeypatch):
    monkeypatch.setattr(geoip, "LIVE_GEOIP", False)

    def _boom(ip):
        raise AssertionError("live lookup should not be called when LIVE_GEOIP is off")

    monkeypatch.setattr(geoip, "_live_country_for_ip", _boom)
    assert geoip.country_for_ip("8.8.8.8") == geoip._mock_country_for_ip("8.8.8.8")


def test_live_mode_falls_back_to_mock_on_failure(monkeypatch):
    monkeypatch.setattr(geoip, "LIVE_GEOIP", True)

    def _fail(ip):
        raise TimeoutError("network unreachable")

    monkeypatch.setattr(geoip, "_live_country_for_ip", _fail)
    assert geoip.country_for_ip("8.8.8.8") == geoip._mock_country_for_ip("8.8.8.8")


def test_live_mode_uses_live_result_when_available(monkeypatch):
    monkeypatch.setattr(geoip, "LIVE_GEOIP", True)
    monkeypatch.setattr(geoip, "_live_country_for_ip", lambda ip: "FR")
    assert geoip.country_for_ip("8.8.8.8") == "FR"
