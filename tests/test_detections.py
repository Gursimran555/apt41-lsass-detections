import json
import sys
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import convert   # noqa: E402
import evaluate  # noqa: E402

RULES = sorted((ROOT / "rules").glob("*.yml"))
LEGACY = sorted((ROOT / "legacy").glob("*.yml"))
SAMPLES = json.loads((ROOT / "samples" / "events.json").read_text())


@pytest.mark.parametrize("path", RULES + LEGACY, ids=lambda p: p.name)
def test_rule_parses_with_pysigma(path):
    collection = SigmaCollection.from_yaml(path.read_text())
    assert len(collection.rules) == 1
    rule = yaml.safe_load(path.read_text())
    assert "attack.t1003.001" in rule["tags"]
    assert rule["level"] in {"low", "medium", "high", "critical"}


def test_rule_ids_unique():
    ids = [yaml.safe_load(p.read_text())["id"] for p in RULES + LEGACY]
    assert len(ids) == len(set(ids))


def test_new_rules_catch_every_malicious_sample_and_no_benign_one():
    res = evaluate.run(RULES, SAMPLES)
    for s in SAMPLES:
        hit = any(res[s["id"]].values())
        assert hit == s["malicious"], s["id"]


def test_original_rule_only_catches_the_xp_value():
    res = evaluate.run(LEGACY, SAMPLES)
    caught = [s["id"] for s in SAMPLES if any(res[s["id"]].values())]
    assert caught == ["old-tool-xp-all-access"]


def test_mimikatz_access_mask_is_what_the_source_requests():
    # PROCESS_VM_READ (0x0010) | PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
    mimikatz = next(s for s in SAMPLES if s["id"] == "mimikatz-sekurlsa")
    assert int(mimikatz["event"]["GrantedAccess"], 16) == 0x0010 | 0x1000


def test_all_access_values():
    standard_rights_required, synchronize = 0x000F0000, 0x00100000
    assert standard_rights_required | synchronize | 0xFFF == 0x1F0FFF    # pre-Vista
    assert standard_rights_required | synchronize | 0xFFFF == 0x1FFFFF   # Vista and later


@pytest.mark.parametrize("cond,results,expected", [
    ("a and not b", {"a": True, "b": False}, True),
    ("a and not b", {"a": True, "b": True}, False),
    ("all of sel_*", {"sel_1": True, "sel_2": True, "f": False}, True),
    ("all of sel_*", {"sel_1": True, "sel_2": False}, False),
    ("1 of sel_* and not f", {"sel_1": False, "sel_2": True, "f": False}, True),
    ("(a or b) and c", {"a": False, "b": True, "c": True}, True),
    ("a or b and c", {"a": True, "b": False, "c": False}, True),
])
def test_condition_parser(cond, results, expected):
    assert evaluate.evaluate_condition(cond, results) is expected


def test_modifiers_are_case_insensitive():
    assert evaluate._match_field({"Image": r"C:\WINDOWS\System32\RUNDLL32.EXE"},
                                 "Image|endswith", r"\rundll32.exe")
    assert evaluate._match_field({"CommandLine": "a b c"}, "CommandLine|contains|all", ["a", "c"])
    assert not evaluate._match_field({"CommandLine": "a b"}, "CommandLine|contains|all", ["a", "z"])
    assert not evaluate._match_field({}, "Image|endswith", "x")


def test_conversions_are_up_to_date():
    assert convert.main(["--check"]) == 0


def test_process_access_rule_has_no_kql():
    assert not (ROOT / "conversions" / "lsass_access_dumping_rights.kql").exists()
    assert (ROOT / "conversions" / "lsass_access_dumping_rights.spl").exists()
