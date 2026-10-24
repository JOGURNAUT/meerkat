"""Runs the pipeline against a real, unmodified 2,000-line production
OpenSSH log (loghub/OpenSSH, CC BY 4.0, https://github.com/logpai/loghub)
instead of a hand-crafted sample, so detection is proven against actual
attack traffic, not just a fixture built to make the rules fire."""

from app.ingest import parse_log
from app.rules import detect_brute_force, run_all

REAL_LOG = "sample_logs/openssh_2k_real.log"


def test_real_log_parses_without_error():
    events = parse_log(REAL_LOG, year=2015)
    assert len(events) > 500  # 520 failed + 1 accepted in this dataset


def test_real_log_flags_the_known_brute_force_source():
    events = parse_log(REAL_LOG, year=2015)
    findings = detect_brute_force(events)
    assert len(findings) > 0
    # 112.95.230.3 is a known repeat offender in this dataset
    assert any("112.95.230.3" in line for f in findings for line in f.evidence)


def test_real_log_produces_no_crash_across_all_rules():
    events = parse_log(REAL_LOG, year=2015)
    findings = run_all(events)
    assert all(f.rule in {"brute_force", "impossible_travel", "privilege_escalation"} for f in findings)
