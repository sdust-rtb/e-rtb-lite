"""
Load the public AgentHarm benchmark (UK AI Security Institute) into
E-RTB-Lite arbitration case format for external jury validation (paper sec. 7.6).

Source (public split only; the full benchmark in the AgentHarm paper is 866
scenarios, of which the released public test split contains 88 unique
scenarios = 44 harmful + 44 benign, each in 4 prompt variants):
  https://huggingface.co/datasets/ai-safety-institute/AgentHarm

Mapping per behavior:
  behavior_description = prompt (the task given to the agent)
  observed_actions     = target_functions (planned/executed tool calls)
  gold_label           = 1 (harmful file) / 0 (benign file)

The 4 variants per scenario (detailed_prompt x hint_included) are prompt
perturbations of the same underlying scenario; they are kept as rows and
clustered by scenario_id for scenario-level consensus statistics.

Output: JSON file with a provenance block (source URL, split, download date,
SHA-256 of source files) and the case list. The raw benchmark files are NOT
copied into the artifact; only the derived, de-duplicated case index is.

Usage:
  py -3 scripts/core/load_agentharm.py \
      --source <path to AgentHarm benchmark dir> \
      --out data/external_agentharm_cases.json
"""
import argparse
import hashlib
import json
import os
import sys

AGENTHARM_URL = "https://huggingface.co/datasets/ai-safety-institute/AgentHarm"
PAPER_CITATION = ("Bhardwaj, Pavan, et al. (UK AI Security Institute). "
                  "AgentHarm: A Benchmark for Measuring Harmfulness of AI Agents. "
                  "arXiv:2410.09024, 2024.")

VARIANT_NAMES = {
    (True, True): "detailed_hint",
    (True, False): "detailed_plain",
    (False, True): "brief_hint",
    (False, False): "brief_plain",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_split(path, label, gold, cases):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    behaviors = d.get("behaviors")
    if behaviors is None:
        raise ValueError(f"{path}: no 'behaviors' field found")
    for b in behaviors:
        prompt = (b.get("prompt") or "").strip()
        funcs = b.get("target_functions") or []
        if not prompt or not funcs:
            raise ValueError(f"{path}: behavior id={b.get('id')} has empty prompt or target_functions")
        variant = VARIANT_NAMES.get(
            (bool(b.get("detailed_prompt")), bool(b.get("hint_included")))
        )
        cases.append({
            "case_id": f"AH-{label}-{b['id']}",
            "source": "agentharm",
            "scenario_id": str(b.get("id_original")),
            "variant": variant,
            "name": b.get("name"),
            "category": b.get("category"),
            "behavior_description": prompt,
            "observed_actions": funcs,
            "gold_label": gold,
        })
    return {
        "sha256": sha256_file(path),
        "n_rows": len(behaviors),
        "n_unique_scenarios": len({b.get("id_original") for b in behaviors}),
        "canary_guid": d.get("canary_guid"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=r"D:\data\RTB\JISA\CCPE\File\AgentHarm\benchmark",
                    help="directory containing the AgentHarm benchmark JSON files")
    ap.add_argument("--out", default=os.path.join("data", "external_agentharm_cases.json"),
                    help="output path (relative to artifact root)")
    ap.add_argument("--download-date", default="2026-09-09",
                    help="ISO date the public split was downloaded")
    args = ap.parse_args()

    files = {
        "harmful": ("harmful_behaviors_test_public.json", "H", 1),
        "benign": ("benign_behaviors_test_public.json", "B", 0),
    }
    for fn in files.values():
        p = os.path.join(args.source, fn[0])
        if not os.path.isfile(p):
            sys.exit(f"missing source file: {p}")

    cases = []
    file_meta = {}
    for split, (fn, label, gold) in files.items():
        file_meta[fn] = load_split(os.path.join(args.source, fn), label, gold, cases)

    cases.sort(key=lambda c: c["case_id"])

    expected = {"harmful_behaviors_test_public.json": 176, "benign_behaviors_test_public.json": 176}
    for fn, n in expected.items():
        if file_meta[fn]["n_rows"] != n:
            sys.exit(f"row count mismatch for {fn}: got {file_meta[fn]['n_rows']}, expected {n}")

    out = {
        "provenance": {
            "dataset": "AgentHarm (public test split)",
            "source_url": AGENTHARM_URL,
            "citation": PAPER_CITATION,
            "split_note": ("public released split: 88 unique scenarios (44 harmful + 44 benign, "
                           "category-matched); 4 prompt variants per scenario "
                           "(detailed_prompt x hint_included) = 352 rows. The full benchmark "
                           "in the AgentHarm paper is 866 scenarios including a private "
                           "split that is not publicly released."),
            "download_date": args.download_date,
            "license": "check dataset card before reuse/redistribution",
            "chat_split": "excluded (44 chat-only rows have no agent tool calls; not usable for jury arbitration)",
            "validation_split": "excluded (reserved as holdout, not part of the reported experiment)",
            "source_files": file_meta,
        },
        "cases": cases,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    import collections
    by_label = collections.Counter(c["gold_label"] for c in cases)
    by_cat = collections.Counter(c["category"] for c in cases)
    by_scen = len({(c["gold_label"], c["scenario_id"]) for c in cases})
    print(f"[load_agentharm] cases={len(cases)} "
          f"(harmful={by_label[1]}, benign={by_label[0]})")
    print(f"[load_agentharm] unique scenarios (label x id)={by_scen} (expected 88)")
    print(f"[load_agentharm] categories: {dict(by_cat)}")
    print(f"[load_agentharm] -> {args.out}")


if __name__ == "__main__":
    main()
