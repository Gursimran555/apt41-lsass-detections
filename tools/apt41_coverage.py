#!/usr/bin/env python3
"""Which APT41 techniques have public Sigma detections?

    python tools/apt41_coverage.py --attack enterprise-attack-20.0.json --sigma path/to/sigma

--attack  an ATT&CK Enterprise STIX bundle (mitre-attack/attack-stix-data)
--sigma   a checkout of SigmaHQ/sigma

Writes reports/apt41-coverage.md and layers/apt41-sigma-coverage.json (an ATT&CK
Navigator layer: score = number of SigmaHQ rules tagged with the technique).

Only techniques ATT&CK maps *directly* to APT41 (G0096) are counted, not every
technique of every tool the group has used. Rules tagged with a technique's old ID
(before ATT&CK renumbered it) are counted too.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GROUP = "G0096"


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def apt41_techniques(bundle_path: Path) -> tuple[dict, dict, dict]:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}
    group = next(o for o in objs if o["type"] == "intrusion-set" and ext_id(o) == GROUP)
    techniques = {}
    for r in objs:
        if (r["type"] == "relationship" and r["relationship_type"] == "uses" and live(r)
                and r["source_ref"] == group["id"]):
            t = by_id.get(r["target_ref"])
            if t and t["type"] == "attack-pattern" and live(t):
                techniques[ext_id(t)] = {
                    "name": t["name"],
                    "tactics": [k["phase_name"] for k in t.get("kill_chain_phases", [])],
                    "procedure": r.get("description", ""),
                }
    # Techniques renumbered in this release: new ID -> old IDs. Sigma rules written
    # before the change are still tagged with the old ID.
    aliases = collections.defaultdict(list)
    for r in objs:
        if r["type"] == "relationship" and r["relationship_type"] == "revoked-by":
            old, new = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
            if old and new and old["type"] == "attack-pattern":
                aliases[ext_id(new)].append(ext_id(old))
    return techniques, group, aliases


def sigma_counts(sigma_root: Path) -> collections.Counter:
    counts = collections.Counter()
    for f in sigma_root.rglob("*.yml"):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or doc.get("status") == "deprecated":
            continue
        for tag in doc.get("tags") or []:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
            if m:
                counts[m.group(1).upper()] += 1
    return counts


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", required=True, type=Path)
    ap.add_argument("--sigma", required=True, type=Path)
    ap.add_argument("--attack-version", default="20.0")
    ap.add_argument("--sigma-commit", default="")
    args = ap.parse_args(argv)

    techniques, group, aliases = apt41_techniques(args.attack)
    counts = sigma_counts(args.sigma)

    rows = []
    for tid, t in sorted(techniques.items()):
        ids = [tid] + aliases.get(tid, [])
        exact = sum(counts.get(i, 0) for i in ids)
        with_subs = exact + sum(c for k, c in counts.items()
                                if any(k.startswith(i + ".") for i in ids))
        name = t["name"] + (f" (was {', '.join(aliases[tid])})" if aliases.get(tid) else "")
        rows.append((tid, name, ", ".join(t["tactics"]), exact, with_subs))

    zero = [r for r in rows if r[4] == 0]
    tactic_counts = collections.Counter(tac for t in techniques.values() for tac in t["tactics"])

    md = [f"# APT41 (G0096) technique coverage in SigmaHQ\n",
          f"ATT&CK Enterprise {args.attack_version}, SigmaHQ"
          + (f" @ `{args.sigma_commit[:7]}`" if args.sigma_commit else "") + ".\n",
          f"- Techniques and sub-techniques mapped directly to APT41: **{len(rows)}**",
          f"- With at least one SigmaHQ rule (counting sub-technique rules for parents): "
          f"**{len(rows) - len(zero)}**",
          f"- With no rule tagged with that ID: **{len(zero)}**\n",
          "## By tactic\n", "| Tactic | Techniques |", "|---|---|"]
    md += [f"| {tac} | {n} |" for tac, n in tactic_counts.most_common()]
    md += ["\n## No SigmaHQ rule tagged with this ID\n",
           "Rules tagged only with the parent technique are not counted here, so for "
           "sub-techniques the parent column shows what exists one level up.\n",
           "| ID | Technique | Tactic | Rules on parent |", "|---|---|---|---|"]
    md += [f"| {r[0]} | {r[1]} | {r[2]} | "
           f"{counts.get(r[0].split('.')[0], 0) if '.' in r[0] else '-'} |" for r in zero]
    md += ["\n## All techniques\n", "| ID | Technique | Tactic | Rules (exact) | Rules (incl. subs) |",
           "|---|---|---|---|---|"]
    md += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |" for r in rows]
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "apt41-coverage.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    layer = {
        "name": f"APT41 (G0096) - SigmaHQ rule count",
        "versions": {"attack": args.attack_version.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Score = SigmaHQ rules tagged with the technique (including sub-techniques). "
                       "0 = no SigmaHQ rule tagged with this ID.",
        "techniques": [{"techniqueID": r[0], "score": r[4],
                        "comment": f"{r[4]} SigmaHQ rule(s)", "enabled": True} for r in rows],
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 20},
        "legendItems": [{"label": "No SigmaHQ rule tagged with this ID", "color": "#ff6666"}],
    }
    (ROOT / "layers").mkdir(exist_ok=True)
    (ROOT / "layers" / "apt41-sigma-coverage.json").write_text(json.dumps(layer, indent=2),
                                                               encoding="utf-8")
    print(f"{len(rows)} techniques, {len(zero)} without a public Sigma rule")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
