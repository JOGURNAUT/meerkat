# Meerkat

A log-based intrusion detection pipeline: feed it an sshd/sudo auth log,
it detects brute-force logins, impossible-travel logins, and privilege
escalation from a previously-unseen source, and reports each one with
the exact evidence lines that justify it.

## Why it's built this way

**Detection is a set of deterministic rules, not a model.** Every finding
carries a `reasons` list built from the actual numbers involved: the
attempt count, the time gap, the countries compared, the command run.
A SOC analyst reading the output can check the math themselves instead
of trusting a score. This mirrors the design used in
[Mongoose](https://github.com/JOGURNAUT/mongoose) and
[Woodpecker](https://github.com/JOGURNAUT/woodpecker): the model, if
there is one, stays advisory; a deterministic stage makes the call.

**Zero runtime dependencies.** Parsing, rules, and the CLI are stdlib
only (`re`, `datetime`, `argparse`, `dataclasses`) — same stance as
Woodpecker. It installs and runs anywhere Python 3.10+ does, with
nothing to pin or break.

**Geo-IP is mocked, deterministically.** There's no free, keyless geo-IP
API worth depending on for a demo, so `app/geoip.py` derives a country
from a hash of the IP itself — the same IP always resolves to the same
country, across runs, so impossible-travel detection is reproducible
without a live API or key. Swapping in a real provider only touches
that one function.

## Running it

```bash
python -m app.cli sample_logs/auth.log --year 2026
```

Exit code is `1` if any findings were produced, `0` if the log is clean
— so it drops straight into a CI step or a cron job without extra
glue. `sample_logs/auth.log` is a synthetic log that deliberately
contains all three patterns:

- a 5-attempt brute-force burst against `203.0.113.7`
- `carol` logging in from Japan, then from Russia, 20 minutes later
- `bob` running `sudo` to root 2.5 minutes after his first-ever login
  from a new source IP

Run it against your own log:

```bash
python -m app.cli /var/log/auth.log
```

(no `--year` needed if the log is from the current year)

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

17 tests, no network calls. They cover: the syslog parser for each
event type, each rule's boundary conditions (brute-force needs both
the count *and* the window; impossible travel needs both the country
mismatch *and* the time gap; privilege escalation only fires when the
*most recent* login — not just any past login — was from a new
source), and an end-to-end CLI run against the sample log asserting
all three rules fire together.

## Architecture

```
app/
  ingest.py   regex parser: sshd/sudo syslog lines -> LogEvent
  geoip.py    deterministic mock IP -> country lookup
  rules.py    detect_brute_force, detect_impossible_travel, detect_privilege_escalation
  models.py   LogEvent / Finding dataclasses
  cli.py      entrypoint: parse a log, run every rule, print a JSON report
tests/
  test_ingest.py          parser correctness per event type
  test_rules.py           rule boundary conditions
  test_cli_integration.py end-to-end run against sample_logs/auth.log
```

## What this doesn't do yet

- Single-host logs only: no correlation across multiple machines or a
  SIEM-style event bus.
- Geo-IP is mocked; a real deployment needs a live provider (MaxMind,
  ipinfo) and realistic travel-time thresholds instead of a flat
  60-minute window.
- No alert delivery (Slack/PagerDuty/ticket) — it prints a report; wiring
  that up is a thin layer on top of `run_all()`.
- Rules run once over a whole log file, not as a streaming tail -f
  pipeline watching a live log in real time.
