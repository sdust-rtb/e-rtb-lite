"""
Load the HarmBench harmful-behavior corpus (Center for AI Safety) into
E-RTB-Lite case format for the one-sided external detection check
(paper sec. 7.6, robustness arm).

Source (test split; MIT license):
  https://github.com/centerforaisafety/HarmBench
  data/behavior_datasets/harmbench_behaviors_text_test.csv

Filter: FunctionalCategory == "standard" (self-contained behaviors, no
ContextString document dependency). This excludes:
  - "contextual" (81 rows): require a ContextString document; multi-doc
    arbitration is out of scope for the reported experiment.
  - "copyright"  (80 rows): graded by hash check on generated text in the
    original framework; outside the security threat model.

HarmBench is a single-label (harmful-only) corpus; gold_label is 1 for every
row. The false-positive control for this one-sided arm comes from the
benign half of AgentHarm (or the synthetic compliant cases), NOT from
HarmBench itself.

Output: JSON with provenance block + case list. Raw data is not copied into
the artifact.

Usage:
  py -3 scripts/core/load_harmbench.py \
      --source <path to behavior_datasets dir> \
      --out data/external_harmbench_cases.json
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import sys

HARMBENCH_URL = "https://github.com/centerforaisafety/HarmBench"
PAPER_CITATION = ("Mazeika, Mantas, et al. "
                  "HarmBench: A Standardized Evaluation Framework for Automated "
                  "Red Teaming and Robust Refusal. arXiv:2402.04249, 2024.")
LICENSE = "MIT"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source",
                    default=r"D:\data\RTB\JISA\CCPE\File\AgentHarm\benchmark\HarmBench-main\data\behavior_datasets",
                    help="directory containing harmbench_behaviors_text_test.csv")
    ap.add_argument("--out", default=os.path.join("data", "external_harmbench_cases.json"),
                    help="output path (relative to artifact root)")
    ap.add_argument("--download-date", default="2026-09-09")
    args = ap.parse_args()

    fn = "harmbench_behaviors_text_test.csv"
    path = os.path.join(args.source, fn)
    if not os.path.isfile(path):
        sys.exit(f"missing source file: {path}")

    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    total = len(rows)
    func = collections.Counter(r["FunctionalCategory"] for r in rows)
    kept = [r for r in rows if r["FunctionalCategory"] == "standard"]
    if len(kept) != 159:
        sys.exit(f"standard-row count mismatch: got {len(kept)}, expected 159")

    cases = []
    seen = set()
    for i, r in enumerate(sorted(kept, key=lambda x: x["BehaviorID"]), start=1):
        beh = (r["Behavior"] or "").strip()
        bid = (r["BehaviorID"] or "").strip()
        if not beh or not bid:
            raise ValueError(f"row {i}: empty Behavior or BehaviorID")
        if bid in seen:
            raise ValueError(f"duplicate BehaviorID: {bid}")
        seen.add(bid)
        cases.append({
            "case_id": f"HBS-{i:03d}-{bid}",
            "source": "harmbench",
            "behavior_id": bid,
            "category": r["SemanticCategory"],
            "behavior_description": beh,
            "gold_label": 1,
        })

    out = {
        "provenance": {
            "dataset": "HarmBench (text test split, standard subset)",
            "source_url": HARMBENCH_URL,
            "citation": PAPER_CITATION,
            "license": LICENSE,
            "version_note": ("downloaded as main-branch zip (HarmBench-main); no git "
                             "metadata preserved, exact commit not recorded"),
            "download_date": args.download_date,
            "split": "harmbench_behaviors_text_test.csv (320 rows total in file)",
            "filter": "FunctionalCategory == 'standard' (159 rows); contextual (81) and copyright (80) excluded",
            "label_note": "single-label harmful-only corpus; gold_label=1 for all rows; FPR control must come from elsewhere (AgentHarm benign / synthetic compliant)",
            "source_files": {fn: {"sha256": sha256_file(path), "n_rows": total,
                                  "functional_category": dict(func)}},
        },
        "cases": cases,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    by_cat = collections.Counter(c["category"] for c in cases)
    print(f"[load_harmbench] cases={len(cases)} (all harmful)")
    print(f"[load_harmbench] categories: {dict(by_cat)}")
    print(f"[load_harmbench] -> {args.out}")


if __name__ == "__main__":
    main()
