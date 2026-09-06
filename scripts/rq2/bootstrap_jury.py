"""
Bootstrap + McNemar 检验：验证异构裁决配置相对同质配置的统计显著优势

输入: results/rq2_jury_cases_raw.json (jury_quality.py 生成的per-case数据)
输出: results/rq2_bootstrap_mcnemar.json

论文声明 (§7.5):
  - Bootstrap superiority: 98.8%
  - 95% CI for delta_error: [0.0111, 0.1222]
  - McNemar p < 0.05
"""

import json
import numpy as np
import os
import sys
from pathlib import Path
from datetime import datetime

# ── 配置 ──
DEFAULT_INPUT = "results/rq2_jury_cases_raw.json"
DEFAULT_OUTPUT = "results/rq2_bootstrap_mcnemar.json"
N_BOOTSTRAP = 100000
SEED = 42
CI_LEVEL = 0.95

# ── 配置映射 ──
CONFIG_MAP = {
    "heterogeneous": ["E-RTB-Lite异构", "E-RTB-Lite heterogeneous"],
    "homogeneous":   ["B3同质LLM", "B3 homogeneous LLM", "Homogeneous Qwen×3"],
    "ablation":      ["消融(纯LLM异构)", "Ablation (pure LLM)", "Ablation Qwen+GLM+Llama"],
}


def find_config(all_raw, target_keys):
    """在 all_raw 中找到匹配的配置名"""
    for key in target_keys:
        if key in all_raw:
            return key
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=DEFAULT_INPUT, help="per-case raw JSON 路径")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="输出 JSON 路径")
    parser.add_argument("--n", type=int, default=N_BOOTSTRAP, help="bootstrap 重采样次数")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    # ── 加载数据 ──
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] 文件不存在: {input_path}")
        print(f"  请先运行 'python rq2/jury_quality.py' 生成 per-case 数据")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        all_raw = json.load(f)

    print(f"[1/5] 加载 {input_path}")
    print(f"  检测到配置: {list(all_raw.keys())}")

    # ── 找到异构 & 同质配置 ──
    het_key = find_config(all_raw, CONFIG_MAP["heterogeneous"])
    hom_key = find_config(all_raw, CONFIG_MAP["homogeneous"])
    abl_key = find_config(all_raw, CONFIG_MAP["ablation"])

    if het_key is None or hom_key is None:
        print(f"[ERROR] 找不到异构({het_key})或同质({hom_key})配置")
        sys.exit(1)

    print(f"  异构配置: '{het_key}'")
    print(f"  同质配置: '{hom_key}'")
    if abl_key:
        print(f"  消融配置: '{abl_key}'")

    # ── 提取 per-case verdict ──
    # 每个案件应有 gold_label + 三种配置的verdict
    het_cases = all_raw[het_key]
    hom_cases = all_raw[hom_key]

    # 提取 verdict 与 gold label 匹配情况
    # jury_quality.py 保存的格式: [case_id, events, gold_label, verdict, verdict_correct, thought_trace, ...]
    # 我们需要统一格式，先探测数据结构
    print(f"\n[2/5] 解析 per-case 数据...")
    print(f"  异构案件数: {len(het_cases)}")
    print(f"  同质案件数: {len(hom_cases)}")

    # 尝试不同可能的字段名
    def get_verdict_correct(case):
        """从 case 字典中提取 verdict 是否正确"""
        if isinstance(case, dict):
            for key in ["verdict_correct", "correct", "is_correct"]:
                if key in case:
                    return bool(case[key])
            # 尝试从 verdict 和 gold_label 计算
            if "verdict" in case and "gold_label" in case:
                return bool(case["verdict"]) == bool(case["gold_label"])
            raise KeyError(f"无法提取 verdict_correct，可用字段: {list(case.keys())}")
        return case  # 如果是布尔值直接返回

    try:
        het_correct = [get_verdict_correct(c) for c in het_cases]
        hom_correct = [get_verdict_correct(c) for c in hom_cases]
    except KeyError as e:
        print(f"[ERROR] 数据格式不兼容: {e}")
        print("  请检查 results/rq2_jury_cases_raw.json 的结构")
        sys.exit(1)

    n_cases = len(het_correct)
    if n_cases == 0 or len(hom_correct) == 0:
        print("[ERROR] 无有效案件数据")
        sys.exit(1)
    if n_cases != len(hom_correct):
        print(f"[WARN] 案件数不一致: 异构={n_cases}, 同质={len(hom_correct)}")
        n_cases = min(n_cases, len(hom_correct))
        het_correct = het_correct[:n_cases]
        hom_correct = hom_correct[:n_cases]

    het_correct = np.array(het_correct, dtype=int)
    hom_correct = np.array(hom_correct, dtype=int)
    het_error = 1 - het_correct
    hom_error = 1 - hom_correct

    print(f"  有效案件数: {n_cases}")
    print(f"  异构错误率: {het_error.mean():.4f} ({het_error.sum()}/{n_cases})")
    print(f"  同质错误率: {hom_error.mean():.4f} ({hom_error.sum()}/{n_cases})")

    # ── 提取消融配置（如果有）──
    abl_correct = None
    if abl_key:
        abl_cases = all_raw[abl_key]
        abl_correct = np.array([get_verdict_correct(c) for c in abl_cases], dtype=int)

    # ── Bootstrap 重采样 ──
    print(f"\n[3/5] Bootstrap 重采样 (B={args.n}, seed={args.seed})...")
    rng = np.random.RandomState(args.seed)

    # 存储每次重采样的 delta_error = het_error - hom_error (负值表示 het 更好)
    delta_samples = np.empty(args.n)
    het_wins = 0

    for b in range(args.n):
        idx = rng.randint(0, n_cases, size=n_cases)
        het_err_b = het_error[idx].mean()
        hom_err_b = hom_error[idx].mean()
        delta = het_err_b - hom_err_b  # 期望为负 (het 错误率更低)
        delta_samples[b] = delta
        if het_err_b < hom_err_b:
            het_wins += 1

    superiority = het_wins / args.n
    ci_lo = np.percentile(delta_samples, (1 - CI_LEVEL) / 2 * 100)
    ci_hi = np.percentile(delta_samples, (1 + CI_LEVEL) / 2 * 100)

    # 论文用 hom - het (正值表示 hetero 优势)
    delta_pos = -delta_samples  # 翻转符号使正值=het更好
    ci_lo_pos = -ci_hi
    ci_hi_pos = -ci_lo

    print(f"  异构优于同质比例: {superiority:.4f} ({het_wins}/{args.n})")
    print(f"  Δε = het_error - hom_error = {delta_samples.mean():.4f}")
    print(f"  95% CI [Δε]: [{ci_lo:.4f}, {ci_hi:.4f}]")
    print(f"  95% CI [hom-het]: [{ci_lo_pos:.4f}, {ci_hi_pos:.4f}]")

    # ── McNemar 检验 ──
    print(f"\n[4/5] McNemar 检验...")
    # 构建 2×2 表:
    #              | het correct | het wrong |
    # hom correct  |     a       |     b     |  <- 这些 case hom 对,het 错(b) = het 劣势
    # hom wrong    |     c       |     d     |  <- 这些 case hom 错,het 对(c) = het 优势
    a = ((het_correct == 1) & (hom_correct == 1)).sum()
    b = ((het_correct == 0) & (hom_correct == 1)).sum()
    c = ((het_correct == 1) & (hom_correct == 0)).sum()
    d = ((het_correct == 0) & (hom_correct == 0)).sum()

    print(f"  McNemar 2×2 表:")
    print(f"               het_correct  het_wrong")
    print(f"  hom_correct:     {a:6d}      {b:6d}")
    print(f"  hom_wrong:       {c:6d}      {d:6d}")
    print(f"  b+c = {b+c} (不一致的case数)")

    # McNemar 统计量 (with continuity correction)
    if b + c > 0:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c)
        # p-value: upper tail of chi2 with 1 df
        from scipy.stats import chi2 as chi2_dist
        p_value = chi2_dist.sf(chi2, 1)
    else:
        chi2 = 0.0
        p_value = 1.0

    print(f"  χ² = {chi2:.4f}")
    print(f"  p  = {p_value:.6e}")
    print(f"  显著? {'✓' if p_value < 0.05 else '✗'}")

    # ── 消融配置分析（如有）──
    abl_results = None
    if abl_correct is not None:
        abl_error = 1 - abl_correct
        print(f"\n[4.5] 消融配置 McNemar...")
        abl_b = ((abl_correct == 0) & (hom_correct == 1)).sum()
        abl_c = ((abl_correct == 1) & (hom_correct == 0)).sum()
        if abl_b + abl_c > 0:
            abl_chi2 = (abs(abl_b - abl_c) - 1) ** 2 / (abl_b + abl_c)
            abl_p = chi2_dist.sf(abl_chi2, 1)
        else:
            abl_chi2 = 0.0
            abl_p = 1.0
        print(f"  b(消融对-同质错)={abl_b}, c(消融错-同质对)={abl_c}")
        print(f"  χ² = {abl_chi2:.4f}, p = {abl_p:.6e}")
        print(f"  显著? {'✓' if abl_p < 0.05 else '✗'}")
        abl_results = {
            "b": int(abl_b), "c": int(abl_c),
            "chi2": float(abl_chi2), "p_value": float(abl_p),
            "error_rate": float(abl_error.mean()),
            "significant_05": bool(abl_p < 0.05),
        }

    # ── 保存结果 ──
    print(f"\n[5/5] 保存结果: {Path(args.output)}")
    output = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "input": str(input_path),
            "n_cases": n_cases,
            "het_config": het_key,
            "hom_config": hom_key,
            "abl_config": abl_key,
            "n_bootstrap": args.n,
            "seed": args.seed,
        },
        "het_vs_hom": {
            "het_error_rate": float(het_error.mean()),
            "hom_error_rate": float(hom_error.mean()),
            "abs_reduction": float(het_error.mean() - hom_error.mean()),
            "rel_reduction": float((het_error.mean() - hom_error.mean()) / hom_error.mean()) if hom_error.mean() > 0 else None,
            "bootstrap_superiority": float(superiority),
            "delta_error_mean": float(delta_samples.mean()),
            "delta_error_ci95": [float(ci_lo), float(ci_hi)],
            "delta_pos_ci95": [float(ci_lo_pos), float(ci_hi_pos)],
            "mcnemar": {
                "a": int(a), "b": int(b), "c": int(c), "d": int(d),
                "chi2": float(chi2), "p_value": float(p_value),
                "significant_05": bool(p_value < 0.05),
            },
        },
        "abl_vs_hom": abl_results,
        "paper_claims": {
            "bootstrap_superiority": 0.988,
            "ci95": [0.0111, 0.1222],
            "mcnemar_p_lt": 0.05,
        },
        "match_paper": {
            "bootstrap_superiority_match": abs(superiority - 0.988) < 0.02,
            "ci95_overlap": ci_lo_pos > 0.0111 * 0.5 and ci_hi_pos < 0.1222 * 1.5,
            "mcnemar_significant": p_value < 0.05,
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 60)
    print("  Bootstrap + McNemar 完成")
    print("=" * 60)
    print(f"  异构优势率: {superiority:.4f} (论文: 0.988)")
    print(f"  Δε 95% CI: [{ci_lo_pos:.4f}, {ci_hi_pos:.4f}] (论文: [0.0111, 0.1222])")
    print(f"  McNemar p: {p_value:.2e} {'✓ <0.05' if p_value < 0.05 else '✗ ≥0.05'}")
    print(f"  结果: {args.output}")


if __name__ == "__main__":
    main()
