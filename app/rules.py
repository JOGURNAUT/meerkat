"""
Deterministic detection rules. No LLM, no scoring model: each rule is a
plain threshold or comparison over the parsed events, and every finding
carries the literal evidence lines that justify it. Same philosophy as
Mongoose's classifier — a verdict has to be reproducible and defensible,
not a guess.
"""

from __future__ import annotations

from datetime import timedelta

from app.geoip import country_for_ip
from app.models import EventType, Finding, LogEvent, Severity

# CIS Control 4.5 / common SSH fail2ban defaults treat 5 failed attempts
# as the point past which a login burst stops looking like a fat-fingered
# password and starts looking like a scripted guesser; 5-in-5-minutes
# mirrors fail2ban's own default (maxretry=5, findtime=10m), just tighter.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(minutes=60)
PRIVESC_LOOKBACK = timedelta(minutes=10)


def detect_brute_force(events: list[LogEvent]) -> list[Finding]:
    """>=5 failed logins from the same source IP inside a 5-minute window."""
    findings: list[Finding] = []
    failed = [e for e in events if e.event_type == EventType.FAILED_PASSWORD]

    by_ip: dict[str, list[LogEvent]] = {}
    for e in failed:
        by_ip.setdefault(e.source_ip, []).append(e)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        window: list[LogEvent] = []
        for e in attempts:
            window.append(e)
            window = [w for w in window if e.timestamp - w.timestamp <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                users_tried = sorted({w.user for w in window})
                findings.append(
                    Finding(
                        rule="brute_force",
                        severity=Severity.HIGH,
                        user=users_tried[0] if len(users_tried) == 1 else "<multiple>",
                        reasons=[
                            f"{len(window)} failed logins from {ip} within "
                            f"{BRUTE_FORCE_WINDOW.seconds // 60} minutes",
                            f"usernames attempted: {', '.join(users_tried)}",
                        ],
                        evidence=[w.raw_line for w in window],
                    )
                )
                window = []  # one finding per burst, not one per attempt past the threshold
    return findings


def detect_impossible_travel(events: list[LogEvent]) -> list[Finding]:
    """Same user, two successful logins from different countries, too close in time to be a real trip."""
    findings: list[Finding] = []
    accepted = [e for e in events if e.event_type == EventType.ACCEPTED_PASSWORD]

    by_user: dict[str, list[LogEvent]] = {}
    for e in accepted:
        by_user.setdefault(e.user, []).append(e)

    for user, logins in by_user.items():
        logins.sort(key=lambda e: e.timestamp)
        for prev, curr in zip(logins, logins[1:]):
            gap = curr.timestamp - prev.timestamp
            if gap > IMPOSSIBLE_TRAVEL_WINDOW:
                continue
            prev_country = country_for_ip(prev.source_ip)
            curr_country = country_for_ip(curr.source_ip)
            if prev_country == curr_country:
                continue
            findings.append(
                Finding(
                    rule="impossible_travel",
                    severity=Severity.HIGH,
                    user=user,
                    reasons=[
                        f"login from {prev_country} ({prev.source_ip}) at {prev.timestamp}, "
                        f"then from {curr_country} ({curr.source_ip}) at {curr.timestamp}",
                        f"gap of {gap} is too short for a real trip between those countries",
                    ],
                    evidence=[prev.raw_line, curr.raw_line],
                )
            )
    return findings


def detect_privilege_escalation(events: list[LogEvent]) -> list[Finding]:
    """sudo-to-root shortly after the user's MOST RECENT login, when that login
    came from a source IP never seen for this user before. A later login from
    a known IP clears the flag, even if an earlier new-source login preceded it."""
    findings: list[Finding] = []
    known_ips: dict[str, set[str]] = {}
    # last_login[user] = (event, was_from_a_new_source)
    last_login: dict[str, tuple[LogEvent, bool]] = {}

    for e in events:
        if e.event_type == EventType.ACCEPTED_PASSWORD:
            seen_before = e.source_ip in known_ips.get(e.user, set())
            last_login[e.user] = (e, not seen_before)
            known_ips.setdefault(e.user, set()).add(e.source_ip)

        elif e.event_type == EventType.SUDO and e.target_user == "root":
            entry = last_login.get(e.user)
            if not entry:
                continue
            login_event, was_new_source = entry
            if was_new_source and e.timestamp - login_event.timestamp <= PRIVESC_LOOKBACK:
                findings.append(
                    Finding(
                        rule="privilege_escalation",
                        severity=Severity.MEDIUM,
                        user=e.user,
                        reasons=[
                            f"sudo to root {e.timestamp - login_event.timestamp} after a login "
                            f"from a source IP ({login_event.source_ip}) never seen for this user before",
                            f"command run: {e.command}",
                        ],
                        evidence=[login_event.raw_line, e.raw_line],
                    )
                )
                last_login[e.user] = (login_event, False)  # one finding per new-source login

    return findings


def run_all(events: list[LogEvent]) -> list[Finding]:
    return [
        *detect_brute_force(events),
        *detect_impossible_travel(events),
        *detect_privilege_escalation(events),
    ]
