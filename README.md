[![CI](https://github.com/JOGURNAUT/meerkat/actions/workflows/ci.yml/badge.svg)](https://github.com/JOGURNAUT/meerkat/actions/workflows/ci.yml)

# Meerkat

A log-based intrusion detection pipeline: feed it an sshd/sudo auth log,
it detects brute-force logins, impossible-travel logins, and privilege
escalation from a previously-unseen source, and reports each one with
the exact evidence lines that justify it. Named after the animal that
stands sentinel and watches for threats — same naming convention as
the rest of this portfolio ([Mongoose](https://github.com/JOGURNAUT/mongoose),
[Woodpecker](https://github.com/JOGURNAUT/woodpecker)).

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

**Geo-IP defaults to a deterministic mock, with a real mode available.**
`app/geoip.py` normally derives a country from a hash of the IP itself —
the same IP always resolves to the same country, across runs, so
impossible-travel detection is reproducible in tests without any
network call. Set `MEERKAT_LIVE_GEOIP=1` to query
[ip-api.com](https://ip-api.com)'s free, keyless endpoint instead
(stdlib `urllib`, no new dependency); a failed live lookup falls back
to the mock rather than crashing the pipeline.

**Threshold choices are grounded, not arbitrary.** 5 failed logins in
5 minutes mirrors fail2ban's own default (`maxretry=5`, `findtime=10m`,
just tighter) and CIS Control 4.5's guidance on account lockout — see
the comment above `BRUTE_FORCE_THRESHOLD` in `app/rules.py`.

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

## Results on a real log, not just the synthetic sample

`sample_logs/openssh_2k_real.log` is an unmodified 2,000-line production
OpenSSH log from [loghub](https://github.com/logpai/loghub) (CC BY 4.0) —
real attack traffic against a real host, not a fixture built to make the
rules fire:

```bash
python -m app.cli sample_logs/openssh_2k_real.log --year 2015
```

| metric | value |
|---|---|
| lines parsed into events | 518 (520 failed logins, 1 accepted) |
| brute-force findings | 96 bursts, almost all from `112.95.230.3`, a repeat offender in this dataset |
| impossible-travel findings | 0 (only 1 accepted login in the whole log — correctly nothing to compare) |
| privilege-escalation findings | 0 (no `sudo` activity in this dataset) |

The two zero counts are as informative as the 96: the rules don't fire
on data that has no basis for firing, which is what "deterministic"
should mean in practice, not just in the design doc.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

24 tests, no network calls by default. They cover: the syslog parser
for each event type, each rule's boundary conditions (brute-force needs
both the count *and* the window; impossible travel needs both the
country mismatch *and* the time gap; privilege escalation only fires
when the *most recent* login — not just any past login — was from a
new source), the live/mock geo-IP fallback behavior, an end-to-end CLI
run against the synthetic sample, and a run against the real log above.

## Architecture

```
app/
  ingest.py   regex parser: sshd/sudo syslog lines -> LogEvent
  geoip.py    IP -> country lookup: deterministic mock by default, opt-in live mode
  config.py   env-driven config (MEERKAT_LIVE_GEOIP)
  rules.py    detect_brute_force, detect_impossible_travel, detect_privilege_escalation
  models.py   LogEvent / Finding dataclasses
  cli.py      entrypoint: parse a log, run every rule, print a JSON report
tests/
  test_ingest.py          parser correctness per event type
  test_rules.py           rule boundary conditions
  test_geoip.py           mock/live/fallback behavior
  test_cli_integration.py end-to-end run against sample_logs/auth.log
  test_real_log.py        end-to-end run against a real production log
```

## What this doesn't do yet

- Single-host logs only: no correlation across multiple machines or a
  SIEM-style event bus.
- Live geo-IP (ip-api.com) is free-tier and rate-limited (45 req/min);
  a real deployment would want a paid provider (MaxMind, ipinfo) and
  realistic travel-time-aware thresholds instead of a flat 60-minute
  window.
- No alert delivery (Slack/PagerDuty/ticket) — it prints a report; wiring
  that up is a thin layer on top of `run_all()`.
- Rules run once over a whole log file, not as a streaming tail -f
  pipeline watching a live log in real time.
