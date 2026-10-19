"""
Parses standard sshd/sudo syslog lines into LogEvent objects.

Syslog timestamps carry no year, so the caller supplies one (defaults to
the current year) — fine for a single log file, which never spans a
year boundary in practice.
"""

from __future__ import annotations

import re
from datetime import datetime

from app.models import EventType, LogEvent

_TS_RE = r"(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"

FAILED_RE = re.compile(
    _TS_RE + r".*sshd\[\d+\]: Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2"
)
ACCEPTED_RE = re.compile(
    _TS_RE + r".*sshd\[\d+\]: Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port \d+ ssh2"
)
SUDO_RE = re.compile(
    _TS_RE + r".*sudo:\s+(?P<user>\S+)\s*:.*USER=(?P<target>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.+)"
)


def _parse_ts(ts: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> LogEvent | None:
    line = line.rstrip("\n")

    m = FAILED_RE.search(line)
    if m:
        return LogEvent(
            timestamp=_parse_ts(m["ts"], year),
            event_type=EventType.FAILED_PASSWORD,
            user=m["user"],
            source_ip=m["ip"],
            raw_line=line,
        )

    m = ACCEPTED_RE.search(line)
    if m:
        return LogEvent(
            timestamp=_parse_ts(m["ts"], year),
            event_type=EventType.ACCEPTED_PASSWORD,
            user=m["user"],
            source_ip=m["ip"],
            raw_line=line,
        )

    m = SUDO_RE.search(line)
    if m:
        return LogEvent(
            timestamp=_parse_ts(m["ts"], year),
            event_type=EventType.SUDO,
            user=m["user"],
            target_user=m["target"],
            command=m["command"].strip(),
            raw_line=line,
        )

    return None


def parse_log(path: str, year: int | None = None) -> list[LogEvent]:
    year = year or datetime.now().year
    events: list[LogEvent] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            event = parse_line(line, year)
            if event:
                events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return events
