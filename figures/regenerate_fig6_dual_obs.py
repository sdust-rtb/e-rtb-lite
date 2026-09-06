"""
Regenerate Figure 6 (Dual Observation Redundancy) for CCPE submission.

Data source: experiments/results/rq2_real_dual_obs.json (baseline trace: 76814
syscall events; n=100 repeats per configuration, 95% CI via normal approx.).

Design goals (per CCPE reviewer):
  - Grouped bar chart: x-axis = loss level, each group has eBPF / LSM / Dual
  - Error bars (95% CI) on ALL configurations, including Dual
  - Clean professional style (no cross-hatching, CCPE-appropriate palette)
  - Significance annotation via caption (figure kept clean)
  - Vector output (PDF) for journal quality
"""
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# ----- data ------------------------------------------------------------------
HERE = Path(r'D:\data\RTB\experiments')
DATA = HERE / "results" / "rq2_real_dual_obs.json"
OUT_DIR = Path(r'D:\data\RTB\JISA\CCPE\File\figure')
OUT = OUT_DIR / "fig10_dual_obs_jisa.pdf"

with DATA.open() as f:
    payload = json.load(f)

rows = payload["results"]
data = {}
for r in rows:
    drop = r["drop"]
    cfg = r["cfg"]
    rate = r["rate"] * 100
    ci = r["ci95"] * 100
    data.setdefault(drop, {})[cfg] = (rate, ci)

loss_levels = sorted(data.keys())
configs     = ["G1_eBPF_only", "G2_LSM_only", "G3_dual"]
labels      = ["Single eBPF", "LSM hooks", "Dual (eBPF + LSM)"]
colors      = ["#C53030", "#2B6CB0", "#4A5568"]

# ----- figure ----------------------------------------------------------------
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        "Times New Roman",
    "mathtext.fontset":  "stix",
    "font.size":         9,
    "axes.titlesize":    10,
    "axes.labelsize":    9,
    "xtick.labelsize":   8.5,
    "ytick.labelsize":   8.5,
    "legend.fontsize":   8.5,
    "axes.linewidth":    0.8,
    "grid.linewidth":    0.4,
    "grid.alpha":        0.55,
})

fig, ax = plt.subplots(figsize=(7.0, 3.6))

n_groups = len(loss_levels)
n_bars   = len(configs)
x = np.arange(n_groups)
width = 0.24

for i, cfg in enumerate(configs):
    vals = [data[d][cfg][0] for d in loss_levels]
    errs = [data[d][cfg][1] for d in loss_levels]
    bars = ax.bar(
        x + (i - 1) * width,
        vals,
        width,
        yerr=errs,
        capsize=2.8,
        color=colors[i],
        edgecolor="#1A202C",
        linewidth=0.55,
        label=labels[i],
        zorder=3,
    )
    for bar, v in zip(bars, vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.6,
            f"{v:.2f}",
            ha="center",
            fontsize=7.4,
            color="#1A202C",
        )

ax.set_ylabel("Detection rate (%)")
ax.set_xlabel("eBPF packet loss rate")
ax.set_xticks(x)
ax.set_xticklabels([f"{int(d*100)}%" for d in loss_levels])
ax.set_ylim(42, 103.5)
ax.grid(axis="y", linestyle="-", which="major", zorder=0)
ax.set_axisbelow(True)

ax.legend(
    ncol=3,
    loc="lower center",
    bbox_to_anchor=(0.5, 1.02),
    frameon=False,
    handlelength=1.0,
)

ax.text(
    0.01, 0.04,
    "Y-axis truncated at 42%\nfor visual clarity",
    transform=ax.transAxes,
    fontsize=6.6,
    color="#718096",
    ha="left",
    va="bottom",
)

fig.tight_layout()
OUT_DIR.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=300, bbox_inches="tight")
print(f"wrote {OUT}")

fig.savefig(OUT.with_suffix(".svg"), bbox_inches="tight")
print(f"wrote {OUT.with_suffix('.svg')}")
