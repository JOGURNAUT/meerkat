from app.ingest import parse_line
from app.models import EventType


def test_parses_failed_password_invalid_user():
    line = "Oct 23 02:14:01 host sshd[2380]: Failed password for invalid user admin from 203.0.113.7 port 51820 ssh2"
    e = parse_line(line, year=2026)
    assert e.event_type == EventType.FAILED_PASSWORD
    assert e.user == "admin"
    assert e.source_ip == "203.0.113.7"
    assert e.timestamp.month == 10 and e.timestamp.day == 23 and e.timestamp.hour == 2


def test_parses_failed_password_valid_user():
    line = "Oct 23 05:45:12 host sshd[5010]: Failed password for dave from 203.0.113.50 port 54010 ssh2"
    e = parse_line(line, year=2026)
    assert e.event_type == EventType.FAILED_PASSWORD
    assert e.user == "dave"


def test_parses_accepted_password():
    line = "Oct 23 01:00:05 host sshd[1001]: Accepted password for alice from 10.0.0.15 port 51000 ssh2"
    e = parse_line(line, year=2026)
    assert e.event_type == EventType.ACCEPTED_PASSWORD
    assert e.user == "alice"
    assert e.source_ip == "10.0.0.15"


def test_parses_sudo():
    line = "Oct 23 03:02:30 host sudo:    bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    e = parse_line(line, year=2026)
    assert e.event_type == EventType.SUDO
    assert e.user == "bob"
    assert e.target_user == "root"
    assert e.command == "/bin/bash"


def test_unrecognized_line_returns_none():
    assert parse_line("this is not a log line", year=2026) is None
