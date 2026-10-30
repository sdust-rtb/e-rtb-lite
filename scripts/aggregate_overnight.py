#!/usr/bin/env python3
"""aggregate_overnight.py — 汇总多智能体过夜 E-RTB 运行并生成对比报告。

用法:
    python3 aggregate_overnight.py [results/overnight_<ts>]

不带参数时自动取最新的 results/overnight_* 目录。
输出: <dir>/overnight_report.json + 终端对比表 (+ 可选 PNG 图)。
"""
import argparse
import glob
import json
import os
import sys
from pathlib import Path


def load_summaries(root: Path):
    """收集每个 agent 的 summary.json，返回 [{scenario, governance, agg, cfg, path}]."""
    items = []
    for sp in sorted(root.rglob("summary.json")):
        try:
            data = json.loads(sp.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  [skip] {sp}: {exc}")
            continue
        cfg = data.get("config", {})
        scenario = cfg.get("scenario")
        governance = cfg.get("governance", "on")
        if not scenario or scenario not in data.get("scenarios", {}):
            continue
        agg = data["scenarios"][scenario]
        items.append({
            "summary_path": str(sp),
            "scenario": scenario,
            "governance": governance,
            "judge": cfg.get("judge"),
            "judge_vendor": cfg.get("judge_vendor"),
            "n": agg.get("n"),
            "agg": agg,
            "cfg": cfg,
        })
    return items


def fmt_r(rows, key, nd=2):
    vals = [r.get("agg", {}).get(key) for r in rows if r.get("agg", {}).get(key) is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals), nd)


def recovery_stats(rows):
    """跨 agent 汇总所有非空 recovery_ms 的均值/中位数/计数。"""
    allr = []
    for r in rows:
        for v in (r.get("agg", {}).get("recovery_ms") or []):
            if v is not None:
                allr.append(v)
    if not allr:
        return None
    allr.sort()
    n = len(allr)
    med = allr[n // 2] if n % 2 else (allr[n // 2 - 1] + allr[n // 2]) / 2
    return {"count": n, "mean": round(sum(allr) / n, 1),
            "median": round(med, 1), "min": round(min(allr), 1), "max": round(max(allr), 1)}


def build_report(items, root):
    groups = {}
    for it in items:
        key = (it["scenario"], it["governance"])
        groups.setdefault(key, []).append(it)

    report = {
        "root": str(root),
        "generated": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "groups": {},
    }
    for (scenario, governance), rows in sorted(groups.items()):
        n_agents = len(rows)
        total_trials = sum((r.get("n") or 0) for r in rows)
        completed = sum(r["agg"].get("completed", 0) for r in rows)
        report["groups"][f"{scenario}/{governance}"] = {
            "agents": n_agents,
            "trials": total_trials,
            "completed": completed,
            "completed_rate": round(completed / total_trials, 3) if total_trials else None,
            "security_blocked_mean": fmt_r(rows, "security_blocked_mean"),
            "avail_blocked_mean": fmt_r(rows, "avail_blocked_mean"),
            "blocked_calls_mean": fmt_r(rows, "blocked_calls_mean"),
            "agent_calls_mean": fmt_r(rows, "agent_calls_mean"),
            "recovery": recovery_stats(rows),
            "verdicts": [v for r in rows for v in (r["agg"].get("verdicts") or [])],
            "judge_accuracy": fmt_r(rows, "judge_accuracy", 3),
            "judge_errors": [e for r in rows for e in (r["agg"].get("judge_errors") or [])],
        }
    return report


def print_report(report):
    g = report["groups"]
    print("\n==== 多智能体过夜 E-RTB 效果报告 ====")
    print(f"根目录: {report['root']}")
    print(f"组数: {len(g)}   生成: {report['generated']}\n")
    hdr = f"{'组':<24}{'agents':>7}{'trials':>8}{'完成率':>9}{'安全拦截均值':>13}{'可用拦截均值':>13}{'恢复ms均值':>12}"
    print(hdr)
    print("-" * len(hdr))
    for key in sorted(g):
        v = g[key]
        rec = v["recovery"]
        print(f"{key:<24}{v['agents']:>7}{v['trials']:>8}"
              f"{(v['completed_rate'] if v['completed_rate'] is not None else '--'):>9}"
              f"{(v['security_blocked_mean'] if v['security_blocked_mean'] is not None else '--'):>13}"
              f"{(v['avail_blocked_mean'] if v['avail_blocked_mean'] is not None else '--'):>13}"
              f"{(rec['mean'] if rec else '--'):>12}")
    print("\n说明:")
    print("  安全拦截均值 = 攻击场景下被治理阻断的违规写（越大越好，on 应 > off）")
    print("  可用拦截均值 = 误报场景下无辜 agent 被暂挂的写（on 应明显 > off=0，这是治理代价）")
    print("  恢复ms       = 无辜裁决后到首次业务写成功的延时（仅 on 组有）")


def plot(report, root):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib import font_manager
    except Exception as exc:
        print(f"\n[plot] 跳过（matplotlib 不可用: {exc}）")
        return None

    # 检测可用的 CJK 字体；无则回退英文标签，避免图上出现方框字形。
    cjk_candidates = ["Noto Sans CJK SC", "Noto Sans CJK JP", "WenQuanYi Zen Hei",
                      "Microsoft YaHei", "SimHei", "Source Han Sans SC", "PingFang SC"]
    installed = {f.name for f in font_manager.fontManager.ttflist}
    cjk_font = next((f for f in cjk_candidates if f in installed), None)
    if cjk_font:
        matplotlib.rcParams["font.sans-serif"] = [cjk_font] + matplotlib.rcParams["font.sans-serif"]
    matplotlib.rcParams["axes.unicode_minus"] = False
    import warnings
    warnings.filterwarnings("ignore", message="Glyph .* missing from font")

    g = report["groups"]

    def val(key, field):
        v = g.get(key, {}).get(field)
        return v if v is not None else 0.0

    L = (lambda zh, en: zh if cjk_font else en)
    labels = []
    sec = []
    comp = []
    for sc in ("attack", "false_alarm"):
        for gov in ("on", "off"):
            k = f"{sc}/{gov}"
            if k in g:
                labels.append(f"{sc}\n{gov}")
                sec.append(val(k, "security_blocked_mean"))
                comp.append(val(k, "completed_rate") * 100)
    if not labels:
        return None

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    colors = ["#c0392b" if "on" in lb else "#7f8c8d" for lb in labels]
    ax1.bar(range(len(labels)), sec, color=colors)
    ax1.set_xticks(range(len(labels)))
    ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_ylabel(L("安全拦截均值", "security_blocked (mean)"))
    ax1.set_title(L("攻击场景：治理开启拦截违规写 vs 对照组",
                    "Attack: governance ON blocks unsafe writes vs control"))
    ax1.grid(axis="y", alpha=0.3)

    ax2.bar(range(len(labels)), comp, color=colors)
    ax2.set_xticks(range(len(labels)))
    ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylabel(L("任务完成率 (%)", "completion rate (%)"))
    ax2.set_title(L("完成率：对照组完成 vs 治理开启被阻断",
                    "Completion: control finishes vs governance ON blocks"))
    ax2.grid(axis="y", alpha=0.3)

    for ax in (ax1, ax2):
        ax.set_ylim(bottom=0)
    fig.tight_layout()
    out = root / "overnight_compare.png"
    fig.savefig(out, dpi=150)
    return str(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=None)
    args = ap.parse_args()

    if args.root:
        root = Path(args.root)
    else:
        cands = sorted(glob.glob("/mnt/d/data/RTB/experiments/results/overnight_*"),
                       reverse=True)
        if not cands:
            print("未找到 results/overnight_* 目录")
            sys.exit(1)
        root = Path(cands[0])
    if not root.is_dir():
        print(f"目录不存在: {root}")
        sys.exit(1)

    items = load_summaries(root)
    if not items:
        print(f"在 {root} 未找到任何 summary.json（可能仍在运行）")
        sys.exit(1)
    report = build_report(items, root)
    (root / "overnight_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print_report(report)
    png = plot(report, root)
    print(f"\n报告: {root / 'overnight_report.json'}")
    if png:
        print(f"图表: {png}")


if __name__ == "__main__":
    main()
