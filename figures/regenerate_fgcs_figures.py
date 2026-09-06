from __future__ import annotations

import json
import math
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
OUT = Path(r"D:\data\RTB\JISA\RTBJISA\fgcs_template\FGCS\figure")


COLORS = {
    "blue": "#4C78A8",
    "light_blue": "#9ecae1",
    "orange": "#F58518",
    "red": "#E45756",
    "green": "#54A24B",
    "teal": "#2CB1A7",
    "purple": "#8E6BBE",
    "gray": "#6B7280",
    "light_gray": "#F3F4F6",
    "border": "#1F2937",
}


def configure_matplotlib() -> None:
    plt.rcParams.update(
        {
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
        }
    )


def save(fig: plt.Figure, stem: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    pdf = OUT / f"{stem}.pdf"
    png = OUT / f"{stem}.png"
    fig.savefig(pdf, bbox_inches="tight", pad_inches=0.04)
    fig.savefig(png, dpi=300, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"saved {pdf}")
    print(f"saved {png}")


def load_json(name: str):
    path = RESULTS / name
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            with path.open("r", encoding=enc) as f:
                return json.load(f)
        except UnicodeDecodeError:
            continue
    with path.open("r") as f:
        return json.load(f)


def add_box(
    ax,
    xy,
    w,
    h,
    text,
    fc="white",
    ec=None,
    lw=1.0,
    r=0.035,
    fontsize=8,
    weight="normal",
    color="#111827",
    ha="center",
):
    ec = ec or COLORS["border"]
    box = FancyBboxPatch(
        xy,
        w,
        h,
        boxstyle=f"round,pad=0.012,rounding_size={r}",
        facecolor=fc,
        edgecolor=ec,
        linewidth=lw,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + w / 2,
        xy[1] + h / 2,
        text,
        ha=ha,
        va="center",
        fontsize=fontsize,
        fontweight=weight,
        color=color,
        linespacing=1.18,
    )
    return box


def arrow(ax, p0, p1, color="#374151", lw=1.0, style="-|>", rad=0.0, mutation=8, ls="-"):
    arr = FancyArrowPatch(
        p0,
        p1,
        arrowstyle=style,
        mutation_scale=mutation,
        linewidth=lw,
        color=color,
        linestyle=ls,
        connectionstyle=f"arc3,rad={rad}",
        shrinkA=2,
        shrinkB=2,
    )
    ax.add_patch(arr)
    return arr


def fig3_timing() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.65))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    actors = [
        ("Agent /\nworkload", 0.08),
        ("eBPF + LSM\nobservers", 0.27),
        ("bsigner\n(TCB)", 0.45),
        ("Risk engine", 0.63),
        ("Heterogeneous\njury", 0.82),
    ]
    y_top, y_bot = 0.78, 0.17
    for label, x in actors:
        ax.text(x, 0.92, label, ha="center", va="center", fontsize=8, fontweight="bold")
        ax.plot([x, x], [y_top, y_bot], color="#9CA3AF", lw=0.8, ls=(0, (3, 3)))

    ax.add_patch(Rectangle((0.04, 0.64), 0.48, 0.11, facecolor="#F9FAFB", edgecolor="none"))
    ax.add_patch(Rectangle((0.52, 0.36), 0.42, 0.15, facecolor="#FDF2F2", edgecolor="none"))
    ax.add_patch(Rectangle((0.04, 0.20), 0.90, 0.09, facecolor="#ECFDF5", edgecolor="none"))
    ax.text(0.055, 0.735, "Fast path", fontsize=7, color=COLORS["gray"], va="center")
    ax.text(0.54, 0.49, "Arbitration path", fontsize=7, color=COLORS["red"], va="center")
    ax.text(0.055, 0.275, "Revocation path", fontsize=7, color=COLORS["green"], va="center")

    steps = [
        ((0.08, 0.78), (0.27, 0.70), "syscall\n<10 us", 0.035),
        ((0.27, 0.70), (0.45, 0.61), "sign\n~84 us", 0.045),
        ((0.45, 0.61), (0.63, 0.53), "risk\n<3 ms", 0.040),
        ((0.63, 0.53), (0.82, 0.43), "jury request\nP50~921 ms", 0.050),
        ((0.82, 0.42), (0.63, 0.32), "verdict"),
        ((0.63, 0.32), (0.27, 0.25), "soft revoke\n~1 ms", -0.050),
        ((0.27, 0.25), (0.08, 0.22), "hard deny\n-EPERM", 0.045),
    ]
    for item in steps:
        if len(item) == 3:
            p0, p1, text = item
            dy = 0.035
        else:
            p0, p1, text, dy = item
        arrow(ax, p0, p1, lw=1.1)
        ax.text((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2 + dy, text, ha="center", fontsize=6.8)

    add_box(
        ax,
        (0.66, 0.62),
        0.27,
        0.115,
        "LLM inference:\nT_arb P50=921.3 ms",
        fc="white",
        ec=COLORS["red"],
        lw=1.0,
        fontsize=7.5,
        weight="bold",
        color=COLORS["red"],
    )
    ax.text(0.95, 0.12, "Time", ha="right", fontsize=8, color=COLORS["gray"])
    arrow(ax, (0.07, 0.13), (0.94, 0.13), color=COLORS["gray"], lw=0.8)
    save(fig, "fig5_timing")


def fig1_overview() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.25))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    planes = [
        (0.05, "Data plane", COLORS["teal"], "Agent runtime\n\neBPF / LSM probes\nkernel observation\n\nTCB separation"),
        (0.365, "Crypto and security plane", COLORS["orange"], "Transparent signer\nprotected process\n\nDCT+ behavior anchor\nhash chain + Ed25519\n\nEvidence pinning"),
        (0.68, "AI governance plane", COLORS["purple"], "Heterogeneous jury\nQwen + GLM + Rego\n\ncommit-reveal vote\naggregation + verdict\n\nPolicy enforcement"),
    ]
    for x, title, color, body in planes:
        add_box(ax, (x, 0.17), 0.27, 0.66, "", fc="#FFFFFF", ec=color, lw=1.15)
        ax.add_patch(Rectangle((x, 0.75), 0.27, 0.08, facecolor=color, edgecolor=color, lw=0))
        ax.text(x + 0.135, 0.79, title, color="white", ha="center", va="center", fontsize=9, fontweight="bold")
        ax.text(x + 0.135, 0.48, body, ha="center", va="center", fontsize=8, linespacing=1.35)
    arrow(ax, (0.32, 0.50), (0.365, 0.50), lw=1.1)
    arrow(ax, (0.635, 0.50), (0.68, 0.50), lw=1.1)
    ax.text(0.342, 0.56, "signed\nevidence", ha="center", fontsize=7)
    ax.text(0.657, 0.56, "risk\ncase", ha="center", fontsize=7)
    add_box(
        ax,
        (0.20, 0.045),
        0.60,
        0.07,
        "Closed loop: observe -> sign -> score -> adjudicate -> revoke",
        fc="#F9FAFB",
        ec="#D1D5DB",
        fontsize=8,
        weight="bold",
    )
    save(fig, "fig1_new")


def fig2_architecture() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.25))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    layers = [
        (0.68, "Layer 1: trusted execution and observation", COLORS["teal"], ["eBPF probes\n(untrusted)", "LSM hooks\n(untrusted)", "Ring buffer", "bsigner\n(trusted TCB)"]),
        (0.41, "Layer 2: adaptive policy and risk assessment", COLORS["orange"], ["Risk scoring\nengine", "DCT+ lifecycle\nmanager", "Reputation\nupdater", "Offline risk\ncontroller"]),
        (0.14, "Layer 3: local heterogeneous ruling", COLORS["purple"], ["Qwen2.5-3B\njuror", "GLM-4-9B\njuror", "Rego rule\nengine", "rho control\nloop"]),
    ]
    for y, title, color, boxes in layers:
        add_box(ax, (0.05, y), 0.90, 0.20, "", fc="#FAFAFA", ec=color, lw=1.0)
        ax.text(0.07, y + 0.16, title, ha="left", va="center", fontsize=8, fontweight="bold")
        xs = [0.10, 0.32, 0.54, 0.76]
        for x, label in zip(xs, boxes):
            ec = COLORS["red"] if "TCB" in label else color
            add_box(ax, (x, y + 0.04), 0.14, 0.085, label, fc="white", ec=ec, lw=0.9, fontsize=7)
    for x in [0.17, 0.39, 0.61, 0.83]:
        arrow(ax, (x, 0.68), (x, 0.61), lw=0.9)
        arrow(ax, (x, 0.41), (x, 0.34), lw=0.9)
    ax.text(0.84, 0.705, "TCB boundary", fontsize=7, color=COLORS["red"])
    save(fig, "fig4_architecture")


def fig4_dctplus() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.15))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    add_box(ax, (0.05, 0.50), 0.43, 0.37, "", fc="#F0FDFA", ec=COLORS["teal"], lw=1.1)
    add_box(ax, (0.52, 0.50), 0.43, 0.37, "", fc="#FFF7ED", ec=COLORS["orange"], lw=1.1)
    ax.text(0.075, 0.82, "Issuance fields (immutable)", fontsize=8.5, fontweight="bold")
    ax.text(0.545, 0.82, "Runtime fields (dynamic)", fontsize=8.5, fontweight="bold")
    immutable = [
        ("DID_A\n32B", 0.10, 0.68),
        ("Node_ID\n32B", 0.23, 0.62),
        ("Container_ID\n32B", 0.35, 0.62),
        ("Chain_Anchor h0\n32B", 0.23, 0.73),
        ("sigma_ow\n64B", 0.36, 0.73),
    ]
    dynamic = [
        ("h_t\n32B", 0.58, 0.71),
        ("seq_t\n8B", 0.70, 0.62),
        ("status\n1B", 0.72, 0.72),
        ("Risk_t\nfloat", 0.84, 0.71),
        ("expiry\n8B", 0.82, 0.62),
    ]
    for label, x, y in immutable:
        add_box(ax, (x, y), 0.105, 0.07, label, fc="white", ec=COLORS["teal"], fontsize=6.7)
    for label, x, y in dynamic:
        add_box(ax, (x, y), 0.105, 0.07, label, fc="white", ec=COLORS["orange"], fontsize=6.7)
    ax.text(0.05, 0.38, "Verification conditions", fontsize=8.5, fontweight="bold")
    checks = [
        "1. sigma_ow verifies against issuer key",
        "2. credential is not expired",
        "3. Node_ID and Container_ID match",
        "4. h_t is a valid successor of Chain_Anchor",
        "5. registry status is not revoked",
    ]
    for i, text in enumerate(checks):
        x = 0.08 if i % 2 == 0 else 0.54
        y = 0.30 - (i // 2) * 0.085
        ax.text(x, y, text, fontsize=7.6, color="#374151")
    add_box(ax, (0.32, 0.045), 0.36, 0.07, "DCT+ is valid only when all five conditions hold.", fc="#F9FAFB", ec="#D1D5DB", fontsize=7.6)
    save(fig, "fig6_dctplus")


def fig5_jury() -> None:
    data = load_json("rq2_jury_results.json")
    if "summary" in data:
        data = data["summary"]

    # Legacy and current result files use different key names.
    def find(match):
        for k, v in data.items():
            s = k + " " + str(v)
            if match in s:
                return v
        raise KeyError(match)

    hetero = find("E-RTB")
    homo = find("B3")
    rho_homo = homo["rho_eff"]
    rho_hetero = hetero["rho_eff"]
    reduction = (rho_homo - rho_hetero) / rho_homo * 100 if rho_homo else 0

    fig, ax = plt.subplots(figsize=(7.0, 3.1))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    add_box(ax, (0.04, 0.12), 0.40, 0.76, "", fc="#FEF7F2", ec=COLORS["orange"], lw=1.0)
    add_box(ax, (0.56, 0.12), 0.40, 0.76, "", fc="#F0FDF4", ec=COLORS["green"], lw=1.0)
    ax.text(0.24, 0.84, "Homogeneous jury", ha="center", fontsize=9, fontweight="bold")
    ax.text(0.76, 0.84, "E-RTB Lite heterogeneous jury", ha="center", fontsize=9, fontweight="bold")

    for i, x in enumerate([0.09, 0.20, 0.31]):
        add_box(ax, (x, 0.61), 0.09, 0.12, f"Qwen\nLLM {i+1}", fc="white", ec=COLORS["red"], fontsize=7.5)
    for x, label, ec in [
        (0.61, "Qwen\nLLM", COLORS["blue"]),
        (0.72, "GLM\nLLM", COLORS["purple"]),
        (0.83, "Rego\nrules", COLORS["green"]),
    ]:
        add_box(ax, (x, 0.61), 0.09, 0.12, label, fc="white", ec=ec, fontsize=7.5)

    ax.plot([0.13, 0.35], [0.53, 0.53], color=COLORS["red"], lw=1.0)
    ax.text(0.24, 0.49, "high shared failure mode", ha="center", fontsize=7, color=COLORS["red"])
    ax.text(0.24, 0.35, rf"$\rho_{{eff}}={rho_homo:.2f}$", ha="center", fontsize=10, color=COLORS["red"], fontweight="bold")

    ax.plot([0.65, 0.87], [0.53, 0.53], color=COLORS["green"], lw=1.0, ls=(0, (4, 2)))
    ax.text(0.76, 0.49, "independent model + rule paths", ha="center", fontsize=7, color=COLORS["green"])
    ax.text(0.76, 0.35, rf"$\rho_{{eff}}={rho_hetero:.2f}$", ha="center", fontsize=10, color=COLORS["green"], fontweight="bold")

    add_box(
        ax,
        (0.60, 0.18),
        0.32,
        0.10,
        rf"{reduction:.0f}% lower effective correlation",
        fc="white",
        ec=COLORS["green"],
        lw=1.0,
        fontsize=8,
        weight="bold",
        color=COLORS["green"],
    )
    add_box(ax, (0.39, 0.36), 0.22, 0.12, "rho monitor\nreplace highly\ncorrelated jurors", fc="white", ec=COLORS["gray"], fontsize=7)
    arrow(ax, (0.50, 0.48), (0.72, 0.61), color=COLORS["gray"], lw=0.9, rad=0.15)
    arrow(ax, (0.50, 0.36), (0.31, 0.61), color=COLORS["gray"], lw=0.9, rad=-0.15, ls="--")
    save(fig, "fig7_jury")


def fig6_deployment() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.45))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.add_patch(
        FancyBboxPatch(
            (0.03, 0.10),
            0.94,
            0.76,
            boxstyle="round,pad=0.015,rounding_size=0.02",
            facecolor="#F9FAFB",
            edgecolor="#9CA3AF",
            linestyle=(0, (5, 3)),
            linewidth=1.0,
        )
    )
    ax.text(0.05, 0.82, "Docker Compose host: WSL2 or cloud Linux", fontsize=8, color=COLORS["gray"])

    add_box(
        ax,
        (0.07, 0.41),
        0.24,
        0.27,
        "Observation container\n\neBPF probes\nLSM hooks\nring buffer",
        fc="white",
        ec=COLORS["green"],
        lw=1.1,
        fontsize=7.8,
        weight="bold",
    )
    add_box(
        ax,
        (0.39, 0.37),
        0.24,
        0.35,
        "Core container\n\nbsigner (TCB)\nDCT+ lifecycle\nOPA risk engine\narbiter",
        fc="#FFF7ED",
        ec=COLORS["orange"],
        lw=1.2,
        fontsize=7.8,
        weight="bold",
    )
    ax.add_patch(Rectangle((0.42, 0.54), 0.18, 0.11, facecolor="none", edgecolor=COLORS["red"], lw=1.0, ls=(0, (3, 2))))
    ax.text(0.51, 0.595, "minimal TCB", ha="center", va="center", fontsize=7, color=COLORS["red"], fontweight="bold")

    add_box(
        ax,
        (0.71, 0.41),
        0.21,
        0.26,
        "Inference container\n\nvLLM Qwen\nvLLM GLM\nRego engine",
        fc="white",
        ec=COLORS["purple"],
        lw=1.1,
        fontsize=7.8,
        weight="bold",
    )
    arrow(ax, (0.31, 0.55), (0.39, 0.55), lw=1.1)
    ax.text(0.35, 0.62, "TLS/HMAC\nevidence", ha="center", fontsize=7)
    arrow(ax, (0.63, 0.55), (0.71, 0.55), lw=1.1)
    ax.text(0.67, 0.62, "HTTP\n:8000", ha="center", fontsize=7)
    arrow(ax, (0.71, 0.48), (0.63, 0.48), lw=1.0, color=COLORS["gray"])
    ax.text(0.67, 0.43, "verdict", ha="center", fontsize=7, color=COLORS["gray"])

    add_box(ax, (0.37, 0.18), 0.28, 0.075, "Registry node / revocation API :5000", fc="white", ec=COLORS["gray"], fontsize=7.4)
    arrow(ax, (0.51, 0.37), (0.51, 0.26), lw=1.0)
    ax.text(
        0.08,
        0.125,
        "Host kernel hooks stay outside the TCB; only bsigner state and key are trusted.",
        fontsize=7.2,
        color=COLORS["gray"],
    )
    save(fig, "fig8_deployment")


def fig7_dual_obs() -> None:
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
                ax.text(bar.get_x() + bar.get_width() / 2, val + 0.9, f"{val:.2f}", ha="center", fontsize=6.8)

    ax.set_ylabel("Observation coverage (%)")
    ax.set_xlabel("eBPF packet loss rate")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(d*100)}%" for d in drops])
    ax.set_ylim(45, 103)
    ax.grid(axis="y", alpha=0.7)
    ax.legend(ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.02), frameon=False)
    ax.annotate(
        "Dual path retains\n99.49% coverage\nat 50% loss",
        xy=(x[-1] + width, 99.49),
        xytext=(x[-1] - 0.3, 83),
        arrowprops=dict(arrowstyle="->", color=COLORS["green"], lw=1.0),
        fontsize=8,
        color=COLORS["green"],
        fontweight="bold",
        ha="center",
    )
    save(fig, "fig10_dual_obss")


def fig8_jury_quality() -> None:
    data = load_json("rq2_jury_results.json")
    if "summary" in data:
        data = data["summary"]

    rows = []
    for key, r in data.items():
        label = r.get("name", key)
        if "E-RTB" in key or "E-RTB" in label:
            short = "E-RTB Lite"
        elif "B3" in key or "B3" in label or "同质" in label:
            short = "Homogeneous"
        else:
            short = "LLM-only"
        rows.append((short, r["fpr"], r["fnr"], r["epsilon"], r["rho_eff"]))
    order = {"E-RTB Lite": 0, "Homogeneous": 1, "LLM-only": 2}
    rows.sort(key=lambda x: order.get(x[0], 99))

    labels = [r[0] for r in rows]
    x = np.arange(len(labels))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.9, 3.1), gridspec_kw={"width_ratios": [1.55, 1]})
    width = 0.24
    metrics = [("FPR", [r[1] for r in rows], COLORS["red"]), ("FNR", [r[2] for r in rows], COLORS["blue"]), ("Total error", [r[3] for r in rows], "#EACB68")]
    for i, (name, vals, color) in enumerate(metrics):
        bars = ax1.bar(x + (i - 1) * width, vals, width, label=name, color=color, edgecolor="#1F2937", linewidth=0.5)
        for bar, val in zip(bars, vals):
            ax1.text(bar.get_x() + bar.get_width() / 2, val + 0.003, f"{val:.4f}", ha="center", fontsize=6.5)
    ax1.set_title("(a) Ruling error rates", loc="left", fontweight="bold")
    ax1.set_ylabel("Rate")
    ax1.set_xticks(x)
    compact_labels = ["E-RTB", "Homo.", "LLM-only"]
    ax1.set_xticklabels(compact_labels)
    ax1.set_ylim(0, max(r[3] for r in rows) * 1.35)
    ax1.grid(axis="y", alpha=0.7)
    ax1.legend(frameon=False, ncol=3, loc="lower left", bbox_to_anchor=(-0.01, 1.02))

    rho_vals = [r[4] for r in rows]
    bars = ax2.bar(x, rho_vals, color=[COLORS["green"], COLORS["red"], COLORS["blue"]], edgecolor="#1F2937", linewidth=0.5)
    for bar, val in zip(bars, rho_vals):
        ax2.text(bar.get_x() + bar.get_width() / 2, val + 0.04, f"{val:.3f}", ha="center", fontsize=7)
    ax2.set_title(r"(b) Effective correlation", loc="left", fontweight="bold")
    ax2.set_ylabel(r"$\rho_{eff}$")
    ax2.set_xticks(x)
    ax2.set_xticklabels(compact_labels)
    ax2.set_ylim(0, max(rho_vals) * 1.22)
    ax2.grid(axis="y", alpha=0.7)
    save(fig, "fig11_jury_quality")


def latest_e2e(prefix: str) -> tuple[Path, dict]:
    candidates = sorted(RESULTS.glob(f"{prefix}_*.json"), key=lambda p: p.stat().st_mtime)
    for p in reversed(candidates):
        data = load_json(p.name)
        if "statistics" in data:
            return p, data
    raise FileNotFoundError(prefix)


def fig9_e2e_latency() -> None:
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

    fig, ax = plt.subplots(figsize=(6.9, 3.35))
    x = np.arange(len(keys))
    width = 0.18
    for i, (name, vals, color) in enumerate(series):
        vals = [max(v, 0.05) for v in vals]
        bars = ax.bar(x + (i - 1.5) * width, vals, width, label=name, color=color, edgecolor="#1F2937", linewidth=0.45)
        for bar, val in zip(bars, vals):
            if (val <= 1.1) or (8 <= val < 100):
                ax.text(bar.get_x() + bar.get_width() / 2, val * 1.08, f"{val:.1f}", ha="center", fontsize=6.3)
    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms, log scale)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.grid(axis="y", which="both", alpha=0.65)
    ax.legend(ncol=4, loc="lower center", bbox_to_anchor=(0.5, 1.02), frameon=False)
    share = real["statistics"]["T_arb(ms)"]["median"] / real["statistics"]["T_e(ms)"]["median"] * 100
    ax.annotate(
        f"LLM arbitration dominates\n{share:.1f}% of real E2E P50",
        xy=(3 + 0.09, real["statistics"]["T_arb(ms)"]["median"]),
        xytext=(2.0, 65),
        arrowprops=dict(arrowstyle="->", color=COLORS["red"], lw=1.0),
        fontsize=8,
        color=COLORS["red"],
        fontweight="bold",
    )
    save(fig, "fig12_e2e_latency")


def status_crossings(status):
    return [i for i in range(1, len(status)) if status[i] != status[i - 1]]


def fig10_dynamics() -> None:
    data = load_json("rq4_dynamics_results.json")
    scenarios = [
        ("burst", "(a) Burst violation"),
        ("sustained", "(b) Persistent moderate violation"),
        ("low_freq", "(c) Low-frequency probing"),
    ]
    fig, axes = plt.subplots(3, 1, figsize=(6.9, 4.55), sharex=True)
    for ax, (key, title) in zip(axes, scenarios):
        rec = data[key]
        s = np.array(rec["step"])
        risk = np.array(rec["Risk_t"], dtype=float)
        rep = np.array(rec["R_t"], dtype=float)
        theta = np.array(rec["theta_warn"], dtype=float)
        ax2 = ax.twinx()
        ax.plot(s, rep, color=COLORS["green"], lw=1.35, label=r"Reputation $R_t$")
        ax2.fill_between(s, risk, color=COLORS["red"], alpha=0.16, step="pre", label=r"Risk $Risk_t$")
        ax2.plot(s, risk, color=COLORS["red"], lw=1.0)
        ax.plot(s, theta, color="#111827", lw=0.9, ls="--", label=r"$\theta_{warn}$")
        ax.axhline(0.5, color="#6B7280", lw=0.8, ls=":", label=r"$\theta_{arb}$")
        for idx in status_crossings(rec["status"]):
            ax.axvline(s[idx], color=COLORS["orange"], lw=0.8, ls=(0, (3, 2)), alpha=0.85)
            ax.text(s[idx] + 1, 0.08, rec["status"][idx - 1] + "->" + rec["status"][idx], fontsize=6.5, color=COLORS["orange"])
        ax.text(0.01, 0.87, title + rf", eta={_eta_label(key)}", transform=ax.transAxes, fontsize=8, fontweight="bold")
        ax.set_ylim(0, 1.02)
        ax2.set_ylim(0, 0.62)
        ax.set_ylabel(r"$R_t$")
        ax2.set_ylabel(r"$Risk_t$", color=COLORS["red"])
        ax2.tick_params(axis="y", colors=COLORS["red"])
        ax.grid(axis="y", alpha=0.65)
        if ax is axes[0]:
            lines1, labs1 = ax.get_legend_handles_labels()
            lines2, labs2 = ax2.get_legend_handles_labels()
            ax.legend(lines1 + lines2, labs1 + labs2, loc="upper right", frameon=False, ncol=4)
    axes[-1].set_xlabel("Time step")
    save(fig, "fig13_dynamics")


def _eta_label(key: str) -> str:
    return {"burst": "0", "sustained": "0.01055", "low_freq": "0.1"}[key]


def main() -> None:
    configure_matplotlib()
    fig1_overview()
    fig2_architecture()
    fig3_timing()
    fig4_dctplus()
    fig5_jury()
    fig6_deployment()
    fig7_dual_obs()
    fig8_jury_quality()
    fig9_e2e_latency()
    fig10_dynamics()


if __name__ == "__main__":
    main()
