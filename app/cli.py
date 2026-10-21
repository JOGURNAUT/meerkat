"""
CLI entrypoint: `python -m app.cli sample_logs/auth.log`
Reads an auth log, runs every detection rule, prints a JSON report.
Batch pipeline, not a live service — same shape as a daily/hourly
log-ingestion job, not a request/response API.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.ingest import parse_log
from app.rules import run_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect brute-force, impossible-travel, and privilege-escalation patterns in an auth log.")
    parser.add_argument("log_path", help="path to an sshd/sudo syslog-style auth log")
    parser.add_argument("--year", type=int, default=None, help="year to assume for syslog timestamps (default: current year)")
    args = parser.parse_args(argv)

    events = parse_log(args.log_path, year=args.year)
    findings = run_all(events)

    report = {
        "log_path": args.log_path,
        "events_parsed": len(events),
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(report, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
