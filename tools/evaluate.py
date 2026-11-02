#!/usr/bin/env python3
"""Replay labelled sample events through Sigma rules.

    python tools/evaluate.py                     # rules/ and legacy/ against samples/events.json

This is a small evaluator for the subset of Sigma these rules use (field maps,
lists, the endswith / startswith / contains / all modifiers, and conditions built
from and / or / not / parentheses / "all of x*" / "1 of x*"). Matching is
case-insensitive, as in Sigma. It is not a replacement for a SIEM; it exists so
the claims in the README are checked by CI.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _match_value(actual, expected: str, mods: list[str]) -> bool:
    if actual is None:
        return False
    a, e = str(actual).lower(), str(expected).lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    return a == e


def _match_field(event: dict, key: str, expected) -> bool:
    field, *mods = key.split("|")
    values = expected if isinstance(expected, list) else [expected]
    hits = [_match_value(event.get(field), v, mods) for v in values]
    return all(hits) if "all" in mods else any(hits)


def _match_detection(event: dict, det) -> bool:
    if isinstance(det, list):                     # list of maps -> OR
        return any(_match_detection(event, d) for d in det)
    return all(_match_field(event, k, v) for k, v in det.items())   # map -> AND


TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\ball of\b|\b1 of\b|[\w*]+)")


def _tokens(cond: str) -> list[str]:
    out, pos = [], 0
    while pos < len(cond):
        m = TOKEN.match(cond, pos)
        if not m:
            raise ValueError(f"cannot parse condition near: {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return [t for t in out if t.strip()]


def evaluate_condition(cond: str, results: dict[str, bool]) -> bool:
    toks = _tokens(cond)
    i = 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def names(pattern):
        found = [n for n in results if fnmatch.fnmatch(n, pattern)]
        if not found:
            raise ValueError(f"no detection matches {pattern}")
        return found

    def primary():
        t = take()
        if t == "(":
            v = expr()
            take()
            return v
        if t == "not":
            return not primary()
        if t == "all of":
            return all(results[n] for n in names(take()))
        if t == "1 of":
            return any(results[n] for n in names(take()))
        return results[t]

    def term():
        v = primary()
        while peek() == "and":
            take()
            v = primary() and v
        return v

    def expr():
        v = term()
        while peek() == "or":
            take()
            v = term() or v
        return v

    return expr()


def load_rule(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def rule_matches(rule: dict, sample: dict) -> bool:
    if rule["logsource"].get("category") != sample["category"]:
        return False
    det = dict(rule["detection"])
    cond = det.pop("condition")
    results = {name: _match_detection(sample["event"], d) for name, d in det.items()}
    return evaluate_condition(cond, results)


def run(rule_paths, samples) -> dict[str, dict[str, bool]]:
    rules = {p.stem: load_rule(p) for p in rule_paths}
    return {s["id"]: {name: rule_matches(r, s) for name, r in rules.items()} for s in samples}


def main() -> int:
    samples = json.loads((ROOT / "samples" / "events.json").read_text())
    legacy = sorted((ROOT / "legacy").glob("*.yml"))
    new = sorted((ROOT / "rules").glob("*.yml"))
    res_old = run(legacy, samples)
    res_new = run(new, samples)

    print(f"{'sample':32} {'label':9} {'original':9} {'new rules'}")
    print("-" * 80)
    tp_old = tp_new = fp_new = 0
    malicious = sum(s["malicious"] for s in samples)
    for s in samples:
        old_hit = any(res_old[s["id"]].values())
        new_hits = [n for n, h in res_new[s["id"]].items() if h]
        tp_old += old_hit and s["malicious"]
        tp_new += bool(new_hits) and s["malicious"]
        fp_new += bool(new_hits) and not s["malicious"]
        label = "malicious" if s["malicious"] else "benign"
        print(f"{s['id']:32} {label:9} {'HIT' if old_hit else '-':9} {', '.join(new_hits) or '-'}")
    access = [s for s in samples if s["category"] == "process_access" and s["malicious"]]
    old_access = sum(any(res_old[s["id"]].values()) for s in access)
    new_access = sum(any(res_new[s["id"]].values()) for s in access)
    print(f"\nLSASS handle-access samples: original rule {old_access}/{len(access)}, "
          f"new rules {new_access}/{len(access)}")
    print(f"original rule: {tp_old}/{malicious} malicious samples detected")
    print(f"new rules:     {tp_new}/{malicious} malicious samples detected, "
          f"{fp_new}/{len(samples) - malicious} benign samples alerted")
    return 0 if tp_new == malicious and fp_new == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
