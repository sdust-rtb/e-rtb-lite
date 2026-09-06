"""
Per-juror (single-juror) error rates.

The jury-level error rate reported in the paper (heterogeneous 6/180, homogeneous
27/180, without-Rego 4/180) is a MAJORITY-VOTE aggregate over three auditors.
Reviewers asked what happens under a single auditor, i.e. what each individual
juror's error rate is and how the majority vote reduces it.

This script is pure post-processing over results/rq2_jury_cases_raw.json
(jury_quality.py output: per-case gold_label + 3 individual votes + majority
verdict). No API calls, no kernel, no cloud.

For each of the three jury configurations it reports, per individual juror:
  * error rate  (vote != gold) with exact Clopper-Pearson 95% CI
  * FPR / FNR
  * error rate split by case category (DV / DC / MS)
  * McNemar test of that juror vs. the jury majority verdict (how much the
    majority vote removes)
  * pairwise error correlation rho_err with the other two jurors
and, for the majority vote itself, the jury-level numbers (sanity check against
the paper: 0.0333 / 0.1500 / 0.0222).

Output: results/rq2_single_juror_stats.json
"""
import json
import math
from pathlib import Path

HERE = Path(r"D:\data\RTB\experiments")
IN = HERE / "results" / "rq2_jury_cases_raw.json"
OUT = HERE / "results" / "rq2_single_juror_stats.json"

PAPER_ERROR_RATE = {  # for cross-checking against the submitted table
    "E-RTB-Lite_heterogeneous": 0.0333,
    "B3_homogeneous": 0.1500,
    "ablation_pure_llm": 0.0222,
}
SHORT = {
    "/public/huggingface-models/Qwen/Qwen2.5-3B-Instruct": "Qwen2.5-3B",
    "/public/huggingface-models/THUDM/glm-4-9b-chat": "GLM-4-9B",
    "DeepSeek-V3.2": "DeepSeek-V3.2",
    "Rego": "Rego (rule engine)",
}


def clopper_pearson(k, n):
    """Exact two-sided 95% CI for a binomial proportion (0 successes handled)."""
    from scipy.stats import beta as beta_dist

    lo = 0.0 if k == 0 else beta_dist.ppf(0.025, k, n - k + 1)
    hi = 1.0 if k == n else beta_dist.ppf(0.975, k + 1, n - k)
    return [float(lo), float(hi)]


def mcnemar(a, b, c):
    """Paired counts -> continuity-corrected McNemar chi2 + p.

    a = both correct, b = juror wrong / majority right,
    c = juror right / majority wrong (unmatched cells not reported).
    """
    if b + c == 0:
        return {"a": int(a), "b": int(b), "c": int(c), "chi2": 0.0, "p_value": 1.0}
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    from scipy.stats import chi2 as chi2_dist

    return {"a": int(a), "b": int(b), "c": int(c), "chi2": float(chi2), "p_value": float(chi2_dist.sf(chi2, 1))}


def phi(a, b, n):
    """Error correlation between two binary predictors (Pearson on 0/1 error flags)."""
    if n == 0:
        return None
    ma = sum(a) / n
    mb = sum(b) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(a, b)) / n
    va = sum((x - ma) ** 2 for x in a) / n
    vb = sum((y - mb) ** 2 for y in b) / n
    if va <= 0 or vb <= 0:
        return None
    return cov / math.sqrt(va * vb)


def juror_stats(cases, idx):
    n = len(cases)
    errs, fp, fn, cats = [], 0, 0, {}
    per_cat = {}
    for c in cases:
        cat = c["case_id"].split("-")[0]
        v = int(c["votes"][idx])
        g = int(c["gold_label"])
        e = int(v != g)
        errs.append(e)
        if v == 1 and g == 0:
            fp += 1
        if v == 0 and g == 1:
            fn += 1
        d = per_cat.setdefault(cat, [0, 0])
        d[0] += 1
        d[1] += e
    err = sum(errs)
    return {
        "engine": SHORT.get(cases[0]["traces"][idx]["engine"], cases[0]["traces"][idx]["engine"]),
        "n": n,
        "errors": err,
        "error_rate": err / n,
        "ci95_clopper_pearson": clopper_pearson(err, n),
        "fpr": fp / n,
        "fnr": fn / n,
        "by_category": {
            cat: {"n": v[0], "errors": v[1], "error_rate": v[1] / v[0]} for cat, v in sorted(per_cat.items())
        },
        "_errors": errs,
    }


def main():
    raw = json.load(open(IN, encoding="utf-8"))
    out = {"metadata": {"input": str(IN), "n_cases": 180, "ci": "exact Clopper-Pearson two-sided 95%"}, "configurations": {}}

    for cfg, cases in raw.items():
        n = len(cases)
        votes = [[int(v) for v in c["votes"]] for c in cases]
        gold = [int(c["gold_label"]) for c in cases]
        maj = [int(c["verdict"]) for c in cases]
        entry = {
            "engine_order": [SHORT.get(t["engine"], t["engine"]) for t in cases[0]["traces"]],
            "jurors": {},
            "jury_majority": {},
            "pairwise_error_correlation": {},
        }

        maj_err = [int(v != g) for v, g in zip(maj, gold)]
        entry["jury_majority"] = {
            "n": n,
            "errors": sum(maj_err),
            "error_rate": sum(maj_err) / n,
            "ci95_clopper_pearson": clopper_pearson(sum(maj_err), n),
            "paper_error_rate": PAPER_ERROR_RATE.get(cfg),
            "matches_paper": abs(sum(maj_err) / n - PAPER_ERROR_RATE.get(cfg, -1)) < 0.0006,
        }

        err_vecs = [[int(c["votes"][i] != c["gold_label"]) for c in cases] for i in range(len(cases[0]["votes"]))]
        for i in range(len(err_vecs)):
            js = juror_stats(cases, i)
            # McNemar: juror vs majority verdict
            a = sum(int(err_vecs[i][k] == 0 and maj_err[k] == 0) for k in range(n))
            b = sum(int(err_vecs[i][k] == 1 and maj_err[k] == 0) for k in range(n))
            c = sum(int(err_vecs[i][k] == 0 and maj_err[k] == 1) for k in range(n))
            js["mcnemar_juror_vs_majority"] = mcnemar(a, b, c)
            js["errors_removed_by_majority"] = js["errors"] - sum(maj_err)
            del js["_errors"]
            entry["jurors"][f"vote[{i}]"] = js

        for i in range(len(err_vecs)):
            for j in range(i + 1, len(err_vecs)):
                key = f"{entry['engine_order'][i]}__{entry['engine_order'][j]}"
                entry["pairwise_error_correlation"][key] = phi(err_vecs[i], err_vecs[j], n)

        # majority-error anatomy: how often did each juror sit with the wrong majority
        for i in range(len(err_vecs)):
            sat = sum(int(maj_err[k] == 1 and err_vecs[i][k] == 1) for k in range(n))
            entry["jurors"][f"vote[{i}]"]["errors_matching_wrong_majority"] = sat
        # unanimous-error rate (all three jurors wrong on the same case)
        unan = sum(int(all(int(c["votes"][k] != c["gold_label"]) for k in range(len(c["votes"])))) for c in cases)
        entry["unanimous_error_cases"] = unan
        entry["unanimous_error_rate"] = unan / n

        out["configurations"][cfg] = entry

    # ── compact key numbers for the paper ──
    key = {}
    for cfg, entry in out["configurations"].items():
        rates = {k: v["error_rate"] for k, v in entry["jurors"].items()}  # keyed by vote index (names repeat)
        names = {k: v["engine"] for k, v in entry["jurors"].items()}
        jury = entry["jury_majority"]["error_rate"]
        best = min(rates, key=rates.get)
        worst = max(rates, key=rates.get)
        key[cfg] = {
            "jury_majority_error_rate": jury,
            "best_juror": names[best],
            "best_juror_error_rate": rates[best],
            "worst_juror": names[worst],
            "worst_juror_error_rate": rates[worst],
            "span_worst_minus_best": rates[worst] - rates[best],
            "jury_vs_worst_juror": jury - rates[worst],
            "jury_vs_best_juror": jury - rates[best],
            "majority_removes_from_worst": rates[worst] - jury,
        }
    out["key_numbers"] = key

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    # ── console report ──
    for cfg, entry in out["configurations"].items():
        print("=" * 78)
        print(cfg, " | engine order:", " / ".join(entry["engine_order"]))
        jm = entry["jury_majority"]
        print(f"  JURY majority      err = {jm['errors']}/{jm['n']} = {jm['error_rate']:.4f} "
              f"CI {jm['ci95_clopper_pearson'][0]:.4f}-{jm['ci95_clopper_pearson'][1]:.4f} "
              f"(paper {jm['paper_error_rate']}, match={jm['matches_paper']})")
        print(f"  unanimous error cases: {entry['unanimous_error_cases']} ({entry['unanimous_error_rate']:.4f})")
        for k, js in entry["jurors"].items():
            print(f"  {js['engine']:<18} err = {js['errors']}/{js['n']} = {js['error_rate']:.4f} "
                  f"CI {js['ci95_clopper_pearson'][0]:.4f}-{js['ci95_clopper_pearson'][1]:.4f} "
                  f"FPR={js['fpr']:.4f} FNR={js['fnr']:.4f} "
                  f"cat=" + ",".join(f"{c}:{v['error_rate']:.3f}" for c, v in js["by_category"].items())
                  + f" | majority-vs-juror McNemar p={js['mcnemar_juror_vs_majority']['p_value']:.2e}")
        for k, v in entry["pairwise_error_correlation"].items():
            print(f"    rho_err {k} = {('undefined (zero-variance juror)' if v is None else format(v, '.4f'))}")

    print("\n" + "=" * 78)
    print("KEY NUMBERS (for the paper)")
    for cfg, v in out["key_numbers"].items():
        print(f"  {cfg}: jury={v['jury_majority_error_rate']:.4f}  best={v['best_juror']} {v['best_juror_error_rate']:.4f}  "
              f"worst={v['worst_juror']} {v['worst_juror_error_rate']:.4f}  span={v['span_worst_minus_best']:.4f}  "
              f"majority-vs-worst reduction={v['majority_removes_from_worst']:.4f}")

    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
