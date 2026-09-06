"""
RQ4: 风险-声誉动力学行为验证

对应 §7.5：
  模式1：突发严重违规（验证定理4.2的响应性）
  模式2：持续中度违规（验证定理4.3的声誉归零）
  模式3：低频试探攻击（验证§4.2.5的对抗持久性）

运行环境：本地（环境1），纯数值模拟
"""

import os
import sys
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DELTA = 30
W_RULES = [0.4, 0.3, 0.3]
GAMMA = 0.05
ETA = 1.0
R_REWARD = 0.1
R_MIN, R_MAX = 0.0, 1.0
ALPHA = 0.5
W0 = 0.8
THETA_WARN_0 = 0.25
THETA_ARB = 0.5
THETA_REVOKE = 0.9
LAMBDA_SENS = 1.0
THETA_MIN = 0.1
TAU_COOL = 10


class RiskEngine:
    def __init__(self, n_rules=3, window=DELTA):
        self.n_rules = n_rules
        self.window = window
        self.history = []

    def update(self, deltas):
        self.history.append(deltas)
        if len(self.history) > self.window:
            self.history = self.history[-self.window:]
        return sum(W_RULES[k] * max(row[k] for row in self.history) for k in range(self.n_rules))


class ReputationTracker:
    def __init__(self, R_init=0.8):
        self.R_t = R_init

    def update(self, risk_t, eta=ETA):
        self.R_t = np.clip((1 - GAMMA) * self.R_t + GAMMA * R_REWARD - eta * risk_t, R_MIN, R_MAX)
        return self.R_t


def compute_W_t(R_t, s_A=0.8):
    return ALPHA * s_A + (1 - ALPHA) * R_t


def compute_theta_warn(W_t):
    return max(THETA_MIN, THETA_WARN_0 * (1 - LAMBDA_SENS * (W0 - W_t)))


def simulate_pattern(mode, n_steps=150, seed=42):
    np.random.seed(seed)
    risk_eng = RiskEngine()
    rep = ReputationTracker()
    rec = {"step": [], "Risk_t": [], "R_t": [], "W_t": [], "theta_warn": [], "status": []}
    status, cooldown, verdict = "A", 0, 0

    for t in range(n_steps):
        if mode == "burst":
            deltas = [1.0, 0.0, 0.0] if t == 21 else [0.0, 0.0, 0.0]
            risk_t = sum(W_RULES[k] * deltas[k] for k in range(3))
            eta_eff = 0.0
        elif mode == "sustained":
            deltas = [0.5, 0.5, 0.5]
            risk_t = risk_eng.update(deltas)
            eta_eff = 0.01055
        elif mode == "low_freq":
            deltas = [0.4, 0.0, 0.0] if t > 0 and t % (DELTA + 5) == 0 else [0.0, 0.0, 0.0]
            risk_t = risk_eng.update(deltas)
            eta_eff = 0.1
        else:
            raise ValueError(mode)

        R_t = rep.update(risk_t, eta=eta_eff)
        W_t = compute_W_t(R_t)
        theta = compute_theta_warn(W_t)

        if status == "A" and risk_t >= theta:
            status, cooldown = "P", TAU_COOL
        elif status == "P":
            if cooldown > 0:
                cooldown -= 1
            elif risk_t < theta and verdict != 1:
                status = "A"
        if risk_t >= THETA_REVOKE or verdict == 1:
            status = "R"

        for k, v in {"step": t, "Risk_t": risk_t, "R_t": R_t, "W_t": W_t,
                      "theta_warn": theta, "status": status}.items():
            rec[k].append(round(v, 6) if isinstance(v, float) else v)
    return rec


def plot_dynamics(rec, mode, output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f"RQ4: Risk-Reputation Dynamics - {mode.upper()} Mode", fontsize=14)
    s = rec["step"]

    axes[0, 0].plot(s, rec["Risk_t"], "b-", lw=1.5, label="$Risk_t$")
    axes[0, 0].axhline(THETA_WARN_0, color="r", ls="--", alpha=0.5, label="$\\theta_{warn}^0$")
    axes[0, 0].set_ylabel("Risk"); axes[0, 0].set_title("(a) Risk Score"); axes[0, 0].legend(); axes[0, 0].grid(alpha=0.3)

    axes[0, 1].plot(s, rec["R_t"], "g-", lw=1.5, label="$R_t$")
    axes[0, 1].set_ylabel("Reputation"); axes[0, 1].set_title("(b) Reputation"); axes[0, 1].legend(); axes[0, 1].grid(alpha=0.3)

    axes[1, 0].plot(s, rec["W_t"], "m-", lw=1.5, label="$W_t$")
    axes[1, 0].set_ylabel("Trust Weight"); axes[1, 0].set_xlabel("Time Step")
    axes[1, 0].set_title("(c) Trust Weight"); axes[1, 0].legend(); axes[1, 0].grid(alpha=0.3)

    axes[1, 1].plot(s, rec["theta_warn"], "r-", lw=1.5, label="$\\theta_{warn}$")
    axes[1, 1].plot(s, rec["Risk_t"], "b--", lw=1, alpha=0.7, label="$Risk_t$")
    for i in range(1, len(s)):
        if rec["status"][i] != rec["status"][i - 1]:
            axes[1, 1].axvline(s[i], color="orange", ls=":", alpha=0.8)
    axes[1, 1].set_ylabel("Threshold / Risk"); axes[1, 1].set_xlabel("Time Step")
    axes[1, 1].set_title("(d) Dynamic Threshold vs Risk"); axes[1, 1].legend(); axes[1, 1].grid(alpha=0.3)

    plt.tight_layout()
    p = os.path.join(output_dir, f"rq4_dynamics_{mode}.png")
    plt.savefig(p, dpi=150); plt.close()
    print(f"  轨迹图: {p}")


def run_all_patterns(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 70)
    print("RQ4: 风险-声誉动力学行为验证")
    print("=" * 70)

    all_results = {}
    for mode in ["burst", "sustained", "low_freq"]:
        print(f"\n[模式] {mode}")
        rec = simulate_pattern(mode)
        all_results[mode] = rec
        print(f"  最终状态={rec['status'][-1]}  声誉={rec['R_t'][-1]:.4f}  信任权重={rec['W_t'][-1]:.4f}")
        plot_dynamics(rec, mode, output_dir)

    p = os.path.join(output_dir, "rq4_dynamics_results.json")
    with open(p, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return all_results


if __name__ == "__main__":
    run_all_patterns()
