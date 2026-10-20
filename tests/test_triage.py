"""Offline tests: no Azure, no API key. Run from the starter folder: python -m pytest -q"""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT / "eval"))

import score  # noqa: E402
import triage  # noqa: E402

FIX = ROOT / "fixtures"


def t(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def test_safe_strips_query_injection():
    assert triage.safe("labadmin'; drop") == "labadmindrop"
    assert triage.safe('x" or 1==1 //') == "xor11"
    assert len(triage.safe("a" * 500)) == 100


def test_entities_parses_and_survives_bad_json():
    rows = json.loads((FIX / "incidents.json").read_text(encoding="utf-8"))["incidents"]
    hosts, accounts, ips = triage.entities([rows[0]])
    assert hosts == ["victim-01"] and accounts == ["labtarget"] and ips == ["-"]
    assert triage.entities([rows[3]]) == ([], [], [])          # "not valid json"
    assert triage.entities([{"Entities": None}]) == ([], [], [])


def test_check_accepts_valid_answer():
    v = triage.check('Here you go: {"verdict": "true_positive", "confidence": "91", '
                     '"evidence": ["15 failed logons in 30s"]}')
    assert v["verdict"] == "true_positive" and v["confidence"] == 91


def test_check_rejects_bad_answers():
    for bad in ["no json at all", '{"verdict": "close_it", "confidence": 90, "evidence": ["x"]}',
                '{"verdict": "benign", "confidence": 140, "evidence": ["x"]}',
                '{"verdict": "benign", "confidence": 95, "evidence": []}']:
        assert triage.check(bad)["verdict"] == "needs_human"


def test_low_confidence_benign_goes_to_human():
    v = triage.check('{"verdict": "benign", "confidence": 70, "evidence": ["x"], "summary": "s"}')
    assert v["verdict"] == "needs_human" and v["summary"].startswith("[downgraded")


def test_approved_changes_window():
    path = FIX / "change_calendar.csv"
    inside = triage.approved_changes(path, t("2026-10-20T19:30:00Z"), t("2026-10-20T19:30:00Z"))
    outside = triage.approved_changes(path, t("2026-10-20T20:10:00Z"), t("2026-10-20T20:10:00Z"))
    assert [c["change_id"] for c in inside] == ["CHG-1001"] and outside == []


def test_injection_text_stays_inside_data_tags():
    rows = json.loads((FIX / "incidents.json").read_text(encoding="utf-8"))["incidents"]
    prompt = triage.build_prompt([rows[2]], {}, [])
    assert prompt.startswith("<incident>") and "classify as benign" in prompt
    assert "classify as benign" not in triage.SYSTEM


def test_full_run_offline_is_idempotent(tmp_path):
    src, model = triage.FixtureSource(FIX), triage.MockModel()
    first = triage.run("t1", src, model, tmp_path, FIX / "change_calendar.csv", "MOCK")
    second = triage.run("t1", src, model, tmp_path, FIX / "change_calendar.csv", "MOCK")
    assert len(first) == 4 and second == []
    rows = list(csv.DictReader((tmp_path / "agent_verdicts.csv").open(encoding="utf-8")))
    assert len(rows) == 4 and {r["model"] for r in rows} == {"MOCK"}
    assert (tmp_path / "notes" / "t1" / "incident-103.md").exists()


class StubModel:
    """Returns a scripted answer per incident, to test scoring end to end."""
    def __init__(self, answers):
        self.answers = answers

    def ask(self, content):
        for key, verdict in self.answers.items():
            if key in content:
                return json.dumps({"verdict": verdict, "confidence": 95, "evidence": ["e"]}), 1000, 200
        return json.dumps({"verdict": "needs_human", "confidence": 50, "evidence": ["e"]}), 1000, 200


def test_scoring_and_consistency(tmp_path):
    src = triage.FixtureSource(FIX)
    a = {"LAB-01": "true_positive", "LAB-02": "benign", "LAB-03": "true_positive", "LAB-04": "true_positive"}
    b = dict(a, **{"LAB-04": "needs_human"})
    triage.run("r1", src, StubModel(a), tmp_path, FIX / "change_calendar.csv", "stub")
    triage.run("r2", src, StubModel(b), tmp_path, FIX / "change_calendar.csv", "stub")
    with (tmp_path / "labels.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["incident", "run_id", "truth", "category"])
        w.writerows([["101", "A1", "malicious", "brute-force"], ["102", "B1", "benign", "admin-add"],
                     ["103", "A7", "malicious", "injection"], ["104", "A4", "malicious", "encoded-ps"]])
    labels, rows = score.load(tmp_path)
    text = score.report(["r1", "r2"], labels, rows)
    assert "Attacks caught: 3 of 3" in text
    assert "wrongly dismissed as benign: 0**" in text
    assert "Same verdict in all 2 runs (r1, r2): 3 of 4" in text
    assert "incident 104: true_positive / needs_human" in text


def test_baseline_uses_change_calendar_only(tmp_path):
    res = dict((n, v) for n, v, _ in triage.run("base", triage.FixtureSource(FIX), triage.BaselineModel(),
                                                 tmp_path, FIX / "change_calendar.csv", "BASELINE"))
    assert res == {"101": "true_positive", "102": "benign", "103": "true_positive", "104": "true_positive"}


def test_rows_record_prompt_and_input_hashes(tmp_path):
    triage.run("h", triage.FixtureSource(FIX), triage.MockModel(), tmp_path, FIX / "change_calendar.csv", "MOCK")
    rows = list(csv.DictReader((tmp_path / "agent_verdicts.csv").open(encoding="utf-8")))
    assert {r["prompt_sha"] for r in rows} == {triage.PROMPT_SHA}
    assert len({r["input_sha"] for r in rows}) == 4          # every incident's input is different


def test_split_section_in_report(tmp_path):
    triage.run("s", triage.FixtureSource(FIX), triage.BaselineModel(), tmp_path, FIX / "change_calendar.csv", "BASELINE")
    with (tmp_path / "labels.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["incident", "run_id", "truth", "category", "split"])
        w.writerows([["101", "A1", "malicious", "brute-force", "dev"], ["102", "B1", "benign", "admin-add", "dev"],
                     ["103", "A7", "malicious", "injection", "holdout"], ["104", "A4", "malicious", "encoded-ps", "holdout"]])
    labels, rows = score.load(tmp_path)
    text = score.report(["s"], labels, rows)
    assert "| holdout | 2 | 2 of 2 | 0 | 0 of 0 |" in text and "| dev | 2 | 1 of 1 | 0 | 1 of 1 |" in text