"""
RQ4 状态机消融实验: 证明软撤销与冷却期的必要性

S1: 无软撤销  — risk 超标不限制权限，等硬撤销
S2: 无冷却期  — 软撤销即刻触发但 risk 回落后立即恢复
S3: 完整闭环  — E-RTB-Lite: 软撤销 + tau_cool 锁定

双尺度风险:
  Risk_short (5-step window): 状态机转移判定 (对近期敏感)
  Risk_long  (30-step window): 声誉计算 (稳态评估)

三个差异场景:
  A: Slow Arbitration  — 软撤销必要性 (S1 仲裁期间全权限)
  B: Fluctuating Risk  — 冷却期必要性 (S2 高频 A<->P 振荡)
  C: Reputation Erosion — 长期治理收敛性 (S3 阈值联动归零)
"""

import os, json, numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

SW_SHORT, SW_LONG = 5, 30
W_RULES = [0.4, 0.3, 0.3]
GAMMA, ETA, R_REWARD = 0.05, 1.0, 0.1
R_MIN, R_MAX = 0.0, 1.0
ALPHA, W0 = 0.5, 0.8
THETA_WARN_0, THETA_ARB, THETA_REVOKE = 0.25, 0.50, 0.90
LAMBDA_SENS, THETA_MIN = 1.0, 0.1
TAU_COOL, ARB_DELAY = 10, 20


class RiskEngine:
    def __init__(self, window):
        self.w, self.h = window, []
    def update(self, deltas):
        self.h.append(deltas)
        if len(self.h) > self.w: self.h = self.h[-self.w:]
        return sum(W_RULES[k] * max(r[k] for r in self.h) for k in range(3))


class RepTracker:
    def __init__(self, R=0.8): self.R = R
    def update(self, r):
        self.R = np.clip((1-GAMMA)*self.R + GAMMA*R_REWARD - ETA*r, R_MIN, R_MAX)
        return self.R


def W_t(R):   return ALPHA*0.8 + (1-ALPHA)*R
def theta(W): return max(THETA_MIN, THETA_WARN_0*(1 - LAMBDA_SENS*(W0 - W)))


CONFIG = {
    "S1": {"soft": False, "cool": False, "label": "S1: No Soft Revoke"},
    "S2": {"soft": True,  "cool": False, "label": "S2: No Cooldown"},
    "S3": {"soft": True,  "cool": True,  "label": "S3: Full Closed-Loop"},
}
COLORS = {"S1": "#E74C3C", "S2": "#F39C12", "S3": "#27AE60"}


# =================================================
# Scenarios
# =================================================

def scenario_slow_arb(t):
    """A: 单次违规 + 20步仲裁延迟"""
    return [0.8, 0.8, 0.0] if t == 20 else [0.0, 0.0, 0.0]


def scenario_fluctuating(t):
    """B: short-period risk spikes (period=8, shorter than cooldown=10)"""
    if t % 8 == 0:
        return [0.9, 0.0, 0.0]
    return [0.0, 0.0, 0.0]


def scenario_erosion(t):
    """C: persistent low-amplitude probes (period=8 < cooldown)"""
    if t % 8 == 0 and t > 0:
        return [0.30, 0.30, 0.0]
    return [0.0, 0.0, 0.0]


# =================================================
# Simulation
# =================================================

def simulate(ck, scenario_fn, sname, n=150, seed=42):
    cfg = CONFIG[ck]; np.random.seed(seed)
    eng_s = RiskEngine(SW_SHORT)
    eng_l = RiskEngine(SW_LONG)
    rep = RepTracker()
    status, cd = "A", 0
    arb_trig, arb_done = False, False
    t_arb_req = None

    rec = dict(step=[], r_short=[], r_long=[], rep=[], wt=[],
               theta=[], status=[])
    first_risk, osc, fr, priv_steps = None, 0, 0, 0

    for t in range(n):
        d = scenario_fn(t)
        rs = eng_s.update(d)
        rl = eng_l.update(d)
        Rt = rep.update(rl)
        wt = W_t(Rt)
        th = theta(wt)

        if first_risk is None and rs >= THETA_WARN_0:
            first_risk = t

        prev = status

        # ---- State machine (uses SHORT risk) ----
        if cfg["soft"]:
            if status == "A" and rs >= th:
                status, cd = "P", TAU_COOL if cfg["cool"] else 0
                osc += 1
            elif status == "P":
                if cfg["cool"] and cd > 0:
                    cd -= 1
                elif rs < th:
                    status = "A"; osc += 1
                    if rs >= th: fr += 1
        else:
            if status != "R": status = "A"

        # ---- Arbitration (uses LONG risk) ----
        if rl >= THETA_ARB and not arb_trig and status != "R":
            arb_trig, t_arb_req = True, t
        if arb_trig and not arb_done and t - t_arb_req >= ARB_DELAY:
            arb_done = True; status = "R"
        if rl >= THETA_REVOKE: status = "R"

        # ---- Metrics ----
        if prev == "A" and status != "R" and rs >= THETA_WARN_0:
            priv_steps += 1  # S1-only: full privilege despite elevated short risk

        for k, v in dict(step=t, r_short=rs, r_long=rl, rep=Rt, wt=wt,
                         theta=th, status=status).items():
            rec[k].append(round(v, 6) if isinstance(v, float) else v)

    exp_win = None
    if first_risk is not None:
        rstep = next((i for i, s in enumerate(rec["status"]) if s == "R"), n-1)
        exp_win = rstep - first_risk

    p_frac = round(sum(1 for s in rec["status"] if s == "P") / n, 4)

    return rec, dict(config=ck, scenario=sname,
                     final_status=rec["status"][-1],
                     final_rep=rec["rep"][-1],
                     exposure_window=exp_win,
                     oscillation_count=osc,
                     false_restore_count=fr,
                     privileged_steps=priv_steps,
                     probation_fraction=p_frac,
                     soft_triggered="P" in rec["status"],
                     hard_triggered="R" in rec["status"])


# =================================================
# Plots
# =================================================

def plot_ablation(all_recs, all_m, out_dir="results"):
    os.makedirs(out_dir, exist_ok=True)
    labels = [("slow_arb","Slow Arbitration"),("fluctuating","Fluctuating Risk"),("erosion","Erosion")]
    for sn, st in labels:
        fig, ax = plt.subplots(2,3,figsize=(18,10))
        fig.suptitle(f"State Machine Ablation — {st}", fontsize=14, fontweight="bold")
        for ci, ck in enumerate(["S1","S2","S3"]):
            rec, m = all_recs[(ck,sn)], all_m[(ck,sn)]
            s, c = rec["step"], COLORS[ck]
            ax0 = ax[0,ci]
            ax0.fill_between(s, rec["r_short"], alpha=0.15, color=c)
            ax0.plot(s, rec["r_short"], color=c, lw=1.5, label="RiskShort")
            ax0.plot(s, rec["theta"], "k--", lw=1, alpha=0.5, label="theta")
            ax0.axhline(THETA_ARB, color="purple", ls="-.", alpha=0.4)
            ax0.set_title(CONFIG[ck]["label"], fontsize=11, fontweight="bold", color=c)
            ax0.legend(fontsize=7); ax0.grid(alpha=0.25)
            ax1 = ax[1,ci]
            sv = [{"A":1.0,"P":0.5,"R":0.0}[s] for s in rec["status"]]
            ax1.step(s, sv, color=c, lw=2, where="post")
            ax1.fill_between(s, sv, alpha=0.12, color=c, step="post")
            ax1.set_ylim(-0.1,1.2); ax1.set_yticks([0,0.5,1])
            ax1.set_yticklabels(["Revoked","Prob.","Active"])
            exp = str(m["exposure_window"]) if m["exposure_window"] else "N/A"
            ax1.set_xlabel(f"Exp={exp} Osc={m['oscillation_count']} "
                           f"FR={m['false_restore_count']} Priv={m['privileged_steps']}",
                           fontsize=8)
            ax1.grid(alpha=0.25)
        plt.tight_layout()
        p = os.path.join(out_dir, f"rq4_ablation_{sn}.png")
        plt.savefig(p, dpi=150); plt.close()
        print(f"  Plot: {p}")


# =================================================
# Main
# =================================================

def run_state_ablation(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print("="*70)
    print("RQ4 State Machine Ablation: S1 vs S2 vs S3")
    print("="*70)
    scenarios = [("slow_arb",scenario_slow_arb),("fluctuating",scenario_fluctuating),("erosion",scenario_erosion)]
    all_recs, all_m = {}, {}
    for ck in ["S1","S2","S3"]:
        for sn, sf in scenarios:
            rec, m = simulate(ck, sf, sn)
            all_recs[(ck,sn)] = rec; all_m[(ck,sn)] = m
            exp = str(m["exposure_window"]) if m["exposure_window"] else "N/A"
            print(f"  [{CONFIG[ck]['label']:<22} x {sn:<12}] "
                  f"final={m['final_status']} exp={exp:>4s} osc={m['oscillation_count']:2d} "
                  f"fr={m['false_restore_count']:2d} priv={m['privileged_steps']:3d} "
                  f"Pfrac={m['probation_fraction']:.3f}")

    print(f"\n{'='*70}")
    print("Ablation Summary")
    print(f"{'='*70}")
    for sn, _ in scenarios:
        print(f"\n  [{sn.upper()}]")
        print(f"  {'Config':<22} {'St':<5} {'Exp':<8} {'Osc':<5} {'FR':<5} {'Priv':<6} {'Pfrac':<7}")
        print(f"  {'-'*58}")
        for ck in ["S1","S2","S3"]:
            m = all_m[(ck,sn)]
            exp = str(m["exposure_window"]) if m["exposure_window"] else "N/A"
            print(f"  {CONFIG[ck]['label']:<22} {m['final_status']:<5} {exp:<8} "
                  f"{m['oscillation_count']:<5} {m['false_restore_count']:<5} "
                  f"{m['privileged_steps']:<6} {m['probation_fraction']:<7.3f}")

    # ---- Key Findings ----
    print(f"\n{'='*70}\nKey Findings\n{'='*70}")
    s1e = all_m[("S1","slow_arb")]["exposure_window"]
    s3e = all_m[("S3","slow_arb")]["exposure_window"]
    s1p = all_m[("S1","slow_arb")]["privileged_steps"]
    s3p = all_m[("S3","slow_arb")]["privileged_steps"]
    print(f"  [Slow Arbitration]")
    print(f"    S1 exposure={s1e}, S3 exposure={s3e}")
    print(f"    S1 privileged steps={s1p} (full access during elevated risk)")
    print(f"    S3 privileged steps={s3p} (restricted during arbitration gap)")

    s2o = all_m[("S2","fluctuating")]["oscillation_count"]
    s3o = all_m[("S3","fluctuating")]["oscillation_count"]
    print(f"  [Fluctuating Risk]")
    print(f"    S2 oscillations={s2o}, S3 oscillations={s3o}")
    if s2o > 0 and s3o > 0:
        r = 100*(s2o-s3o)/s2o
        print(f"    Cooldown reduces oscillations by {r:.0f}%")

    s1pr = all_m[("S1","erosion")]["probation_fraction"]
    s3pr = all_m[("S3","erosion")]["probation_fraction"]
    print(f"  [Reputation Erosion]")
    print(f"    S1 P fraction={s1pr:.3f} (no restriction despite erosion)")
    print(f"    S3 P fraction={s3pr:.3f} (active restriction via cooldown)")

    plot_ablation(all_recs, all_m, output_dir)

    out = {
        "experiment": "rq4_state_ablation",
        "configs": {k: v["label"] for k, v in CONFIG.items()},
        "results": {f"{ck}_{sn}": m for (ck, sn), m in all_m.items()},
        "params": {"SW_SHORT":SW_SHORT,"SW_LONG":SW_LONG,"TAU_COOL":TAU_COOL,"ARB_DELAY":ARB_DELAY}
    }
    p = os.path.join(output_dir, "rq4_ablation_results.json")
    with open(p, "w") as f: json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {p}")
    return all_m


def run_ablation(output_dir="results"):
    return run_state_ablation(output_dir)

if __name__ == "__main__":
    run_state_ablation()
