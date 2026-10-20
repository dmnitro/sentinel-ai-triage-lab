# Starter pack: Sentinel lab triage agent

Synthetic sample data in `fixtures/` lets you run and test everything before any Azure account exists.

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q                                              # 12 offline tests
python agent/triage.py base --fixtures fixtures --baseline --changes fixtures/change_calendar.csv   # rule-based baseline
powershell -File detections/tests/build-tests.ps1                 # KQL tests to paste into a free ADX cluster
python agent/triage.py demo --fixtures fixtures --mock --changes fixtures/change_calendar.csv
python agent/triage.py demo2 --fixtures fixtures --changes fixtures/change_calendar.csv   # real Claude, needs ANTHROPIC_API_KEY
python agent/triage.py v1                                        # live: needs az login + WORKSPACE_ID
python eval/score.py v1 v1-r2 v1-r3                              # grid, categories, cost, consistency
```

`--mock` is a fake model for testing the plumbing; its verdicts mean nothing.
`infra/rebuild.ps1` was not run against a live subscription when written; go line by line.