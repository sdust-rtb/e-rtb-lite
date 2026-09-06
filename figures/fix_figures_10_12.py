"""
Regenerate Figure 10 (Dual observation) and Figure 12 (E2E latency)
with reviewer-requested improvements:

Figure 10:
  - Add "Y-axis truncated at 45% for clarity" note
  - Make "Dual path retains 99.49%" annotation more prominent

Figure 12:
  - Add vertical dashed line separating Containment vs Adjudication
  - Label both sides
"""
from __future__ import annotations
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
OUT = ROOT / "figures"
OUT.mkdir(parents=True, exist_ok=True)

COLORS = {
    "blue": "#4C78A8",
    "light_blue": "#9ecae1",
    "orange": "#F58518",
    "red": "#E45756",
    "green": "#54A24B",
    "teal": "#2CB1A7",
    "purple": "#8E6BBE",
    "gray": "#6B7280",
    "border": "#1F2937",
}


def configure():
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8.5,
        "axes.labelsize": 9,
        "axes.titlesize": 9,
        "legend.fontsize": 7.5,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "axes.linewidth": 0.8,
        "axes.edgecolor": COLORS["border"],
        "grid.color": "#D1D5DB",
        "grid.linewidth": 0.45,
    })


def save(fig, stem):
    pdf = OUT / f"{stem}.pdf"
    png = OUT / f"{stem}.png"
    fig.savefig(pdf, bbox_inches="tight", pad_inches=0.04)
    fig.savefig(png, dpi=300, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"saved {pdf}")


def load_json(name):
    path = RESULTS / name
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            with path.open("r", encoding=enc) as f:
                return json.load(f)
        except UnicodeDecodeError:
            continue
    with path.open("r") as f:
        return json.load(f)


def fig10_dual_obs_fixed():
    """Figure 10 with Y-axis truncation note and prominent annotation."""
    data = load_json("rq2_real_dual_obs.json")
    rows = data.get("results") or data.get("drop_test_results")
    norm = []
    for r in rows:
        drop = r.get("drop", r.get("drop_prob"))
        cfg = r.get("cfg", r.get("config"))
        rate = r.get("rate", r.get("mean_rate")) * 100
        ci = r["ci95"] * 100
        norm.append((drop, cfg, rate, ci))

    drops = sorted({r[0] for r in norm})
    configs = ["G1_eBPF_only", "G2_LSM_only", "G3_dual"]
    labels = ["Single eBPF", "LSM only", "Dual observation"]
    colors = [COLORS["blue"], COLORS["light_blue"], COLORS["green"]]
    hatches = ["", "///", "\\\\"]

    fig, ax = plt.subplots(figsize=(6.9, 3.5))
    x = np.arange(len(drops))
    width = 0.24
    for i, cfg in enumerate(configs):
        vals, errs = [], []
        for d in drops:
            row = next(r for r in norm if r[0] == d and r[1] == cfg)
            vals.append(row[2])
            errs.append(row[3])
        bars = ax.bar(
            x + (i - 1) * width,
            vals,
            width,
            yerr=errs,
            capsize=2.2,
            color=colors[i],
            edgecolor="#1F2937",
            linewidth=0.55,
            hatch=hatches[i],
            label=labels[i],
        )
        for bar, val in zip(bars, vals):
            if val >= 99 or i != 1:
                ax.text(bar.get_x() + bar.get_width() / 2, val + 0.9,
                        f"{val:.2f}", ha="center", fontsize=6.8)

    ax.set_ylabel("Observation coverage (%)")
    ax.set_xlabel("eBPF packet loss rate")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(d*100)}%" for d in drops])
    ax.set_ylim(45, 103)
    ax.grid(axis="y", alpha=0.7)
    ax.legend(ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.02), frameon=False)

    # Prominent annotation with background box
    ax.annotate(
        "Dual path retains\n99.49% coverage\nat 50% loss",
        xy=(x[-1] + width, 99.49),
        xytext=(x[-1] - 0.3, 78),
        arrowprops=dict(arrowstyle="->", color=COLORS["green"], lw=1.5,
                        connectionstyle="arc3,rad=0.1"),
        fontsize=9,
        color=COLORS["green"],
        fontweight="bold",
        ha="center",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#ECFDF5",
                  edgecolor=COLORS["green"], alpha=0.9, linewidth=1.2),
    )

    # Y-axis truncation note box in bottom-left corner
    ax.text(
        0.02, 0.05,
        "Y-axis truncated at 45%\nfor visual clarity",
        transform=ax.transAxes,
        fontsize=7,
        color=COLORS["gray"],
        ha="left",
        va="bottom",
        bbox=dict(boxstyle="round,pad=0.25", facecolor="white",
                  edgecolor=COLORS["gray"], alpha=0.85, linewidth=0.6),
    )

    save(fig, "fig10_dual_obss_v2")


def fig12_e2e_latency_fixed():
    """Figure 12 with Containment/Adjudication divider line."""
    mock_path, mock = latest_e2e("e2e_mock")
    real_path, real = latest_e2e("e2e_real")
    print(f"using {mock_path.name} and {real_path.name}")

    keys = ["T_d(ms)", "T_soft(ms)", "T_fast(ms)", "T_arb(ms)", "T_hard(ms)", "T_e(ms)"]
    labels = ["T_d", "T_soft", "T_fast", "T_arb", "T_hard", "T_e2e"]
    series = [
        ("Mock P50", [mock["statistics"][k]["median"] for k in keys], COLORS["blue"]),
        ("Mock P95", [mock["statistics"][k]["p95"] for k in keys], COLORS["light_blue"]),
        ("Real LLM P50", [real["statistics"][k]["median"] for k in keys], "#F6AD55"),
        ("Real LLM P95", [real["statistics"][k]["p95"] for k in keys], COLORS["red"]),
    ]

    fig, ax = plt.subplots(figsize=(7.2, 3.5))
    x = np.arange(len(keys))
    width = 0.18
    for i, (name, vals, color) in enumerate(series):
        vals = [max(v, 0.05) for v in vals]
        bars = ax.bar(x + (i - 1.5) * width, vals, width, label=name,
                      color=color, edgecolor="#1F2937", linewidth=0.45)
        for bar, val in zip(bars, vals):
            if (val <= 1.1) or (8 <= val < 100):
                ax.text(bar.get_x() + bar.get_width() / 2, val * 1.08,
                        f"{val:.1f}", ha="center", fontsize=6.3)
    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms, log scale)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.grid(axis="y", which="both", alpha=0.65)
    ax.legend(ncol=4, loc="lower center", bbox_to_anchor=(0.5, 1.02), frameon=False)

    # Vertical dashed divider between Containment and Adjudication
    # Divider at x=2.5 (between T_fast index=2 and T_arb index=3)
    divider_x = 2.5
    ymin, ymax = ax.get_ylim()
    ax.axvline(x=divider_x, color="#374151", linestyle="--", linewidth=1.2, alpha=0.7, zorder=5)

    # Containment label (left side)
    ax.text(
        divider_x / 2, 0.55,
        "Containment",
        transform=ax.get_xaxis_transform(),
        ha="center", va="center",
        fontsize=9, fontweight="bold",
        color=COLORS["green"],
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#ECFDF5",
                  edgecolor=COLORS["green"], alpha=0.85, linewidth=0.8),
        zorder=6,
    )

    # Adjudication label (right side)
    ax.text(
        (divider_x + len(keys) - 1) / 2, 0.55,
        "Adjudication",
        transform=ax.get_xaxis_transform(),
        ha="center", va="center",
        fontsize=9, fontweight="bold",
        color=COLORS["red"],
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#FEF2F2",
                  edgecolor=COLORS["red"], alpha=0.85, linewidth=0.8),
        zorder=6,
    )

    # Original annotation
    share = real["statistics"]["T_arb(ms)"]["median"] / real["statistics"]["T_e(ms)"]["median"] * 100
    ax.annotate(
        f"LLM arbitration dominates\n{share:.1f}% of real E2E P50",
        xy=(3 + 0.09, real["statistics"]["T_arb(ms)"]["median"]),
        xytext=(1.8, 80),
        arrowprops=dict(arrowstyle="->", color=COLORS["red"], lw=1.0),
        fontsize=8,
        color=COLORS["red"],
        fontweight="bold",
    )

    save(fig, "fig12_e2e_latency_v2")


def latest_e2e(prefix):
    candidates = sorted(RESULTS.glob(f"{prefix}_*.json"), key=lambda p: p.stat().st_mtime)
    for p in reversed(candidates):
        data = load_json(p.name)
        if "statistics" in data:
            return p, data
    raise FileNotFoundError(prefix)


if __name__ == "__main__":
    configure()
    fig10_dual_obs_fixed()
    fig12_e2e_latency_fixed()
