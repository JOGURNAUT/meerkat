from datetime import datetime, timedelta

from app.models import EventType, LogEvent
from app.rules import (
    detect_brute_force,
    detect_impossible_travel,
    detect_privilege_escalation,
)

BASE = datetime(2026, 10, 23, 2, 0, 0)


def _failed(user, ip, offset_seconds):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        event_type=EventType.FAILED_PASSWORD,
        user=user,
        source_ip=ip,
        raw_line=f"<failed {user}@{ip}>",
    )


def _accepted(user, ip, offset_seconds):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        event_type=EventType.ACCEPTED_PASSWORD,
        user=user,
        source_ip=ip,
        raw_line=f"<accepted {user}@{ip}>",
    )


def _sudo(user, target, offset_seconds, command="/bin/bash"):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        event_type=EventType.SUDO,
        user=user,
        target_user=target,
        command=command,
        raw_line=f"<sudo {user}->{target}>",
    )


def test_brute_force_fires_at_threshold():
    events = [_failed("admin", "203.0.113.7", i * 10) for i in range(5)]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert findings[0].rule == "brute_force"
    assert len(findings[0].evidence) == 5


def test_brute_force_does_not_fire_below_threshold():
    events = [_failed("admin", "203.0.113.7", i * 10) for i in range(4)]
    assert detect_brute_force(events) == []


def test_brute_force_requires_the_window_not_just_the_count():
    # 5 attempts, but spread over 20 minutes — outside the 5-minute window
    events = [_failed("admin", "203.0.113.7", i * 300) for i in range(5)]
    assert detect_brute_force(events) == []


def test_brute_force_is_per_source_ip():
    events = [_failed("admin", "1.1.1.1", i * 10) for i in range(3)] + [
        _failed("admin", "2.2.2.2", i * 10) for i in range(3)
    ]
    assert detect_brute_force(events) == []


def test_impossible_travel_fires_on_country_mismatch_within_window():
    events = [_accepted("carol", "1.2.3.4", 0), _accepted("carol", "9.9.9.9", 1200)]  # 20 min apart
    findings = detect_impossible_travel(events)
    assert len(findings) == 1
    assert findings[0].rule == "impossible_travel"
    assert findings[0].user == "carol"


def test_impossible_travel_does_not_fire_same_country():
    events = [_accepted("alice", "10.0.0.15", 0), _accepted("alice", "10.0.0.15", 900)]
    assert detect_impossible_travel(events) == []


def test_impossible_travel_does_not_fire_outside_window():
    events = [_accepted("carol", "1.2.3.4", 0), _accepted("carol", "9.9.9.9", 4000)]  # >60 min
    assert detect_impossible_travel(events) == []


def test_privilege_escalation_fires_after_login_from_new_source():
    events = [_accepted("bob", "198.51.100.44", 0), _sudo("bob", "root", 150)]
    findings = detect_privilege_escalation(events)
    assert len(findings) == 1
    assert findings[0].rule == "privilege_escalation"


def test_privilege_escalation_does_not_fire_for_known_source():
    events = [
        _accepted("bob", "198.51.100.44", 0),
        _accepted("bob", "198.51.100.44", 500),
        _sudo("bob", "root", 550),
    ]
    assert detect_privilege_escalation(events) == []


def test_privilege_escalation_ignores_non_root_sudo():
    events = [_accepted("bob", "198.51.100.44", 0), _sudo("bob", "www-data", 150)]
    assert detect_privilege_escalation(events) == []
