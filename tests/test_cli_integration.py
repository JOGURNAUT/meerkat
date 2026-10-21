import json
import subprocess
import sys
from pathlib import Path

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log"


def test_sample_log_produces_all_three_finding_types():
    result = subprocess.run(
        [sys.executable, "-m", "app.cli", str(SAMPLE_LOG), "--year", "2026"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert result.returncode == 1  # findings present -> non-zero exit
    report = json.loads(result.stdout)

    rules_found = {f["rule"] for f in report["findings"]}
    assert rules_found == {"brute_force", "impossible_travel", "privilege_escalation"}
    assert report["events_parsed"] > 0


def test_clean_log_exits_zero(tmp_path):
    clean_log = tmp_path / "clean.log"
    clean_log.write_text(
        "Oct 23 01:00:05 host sshd[1001]: Accepted password for alice from 10.0.0.15 port 51000 ssh2\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "app.cli", str(clean_log), "--year", "2026"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["findings"] == []
