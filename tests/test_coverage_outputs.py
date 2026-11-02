import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAYER = json.loads((ROOT / "layers" / "apt41-sigma-coverage.json").read_text())
REPORT = (ROOT / "reports" / "apt41-coverage.md").read_text()


def test_layer_shape():
    assert LAYER["domain"] == "enterprise-attack"
    assert LAYER["versions"]["layer"] == "4.5"
    for t in LAYER["techniques"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", t["techniqueID"])
        assert isinstance(t["score"], int) and t["score"] >= 0


def test_layer_and_report_agree():
    n = len(LAYER["techniques"])
    zero = sum(t["score"] == 0 for t in LAYER["techniques"])
    assert f"mapped directly to APT41: **{n}**" in REPORT
    assert f"no rule tagged with that ID: **{zero}**" in REPORT


def test_lsass_memory_is_in_the_apt41_set():
    ids = {t["techniqueID"] for t in LAYER["techniques"]}
    assert "T1003.001" in ids
