"""
Bursty-loss extension of the dual-observation experiment.

The original experiment (rq2/ebpf_runner.py::run_dual_obs_experiment) simulates
UNIFORM i.i.d. packet loss: for each of N baseline samples,
    ebpf_ok = (random() > drop)   (independent per event)
    lsm_ok  = (random() > 0.01)   (independent per event)
with N=10000, n_repeats=100, and a normal-approx 95% CI.

This script reuses the SAME baseline sample set and the SAME detection
definition, but drives the eBPF channel with a two-state Markov chain
(KEEP/DROP) that produces consecutive (bursty) drop runs. We calibrate the
chain so the *mean* drop fraction is still 50% (matching the 50% case in the
paper) while varying the mean drop-run length L = 1/beta:
    P(KEEP->DROP) = alpha, P(DROP->KEEP) = beta, alpha = beta  =>  P(DROP)=0.5
    mean drop-run length = 1/beta.

This is pure post-processing on existing data (no eBPF/cloud/kernel needed).
A fixed seed is recorded for reproducibility.
"""
import json
import math
import random
from pathlib import Path

HERE = Path(r"D:\data\RTB\experiments")
DATA = HERE / "results" / "rq2_real_dual_obs.json"
OUT = HERE / "results" / "rq2_dual_obs_bursty.json"

LSM_DROP = 0.01          # per-event LSM loss (matches original)
NREP = 100               # repeats (matches original)
SEED = 20260905          # recorded for reproducibility

payload = json.load(open(DATA, encoding="utf-8"))
samples = payload["baseline"]["samples"]
N = len(samples)
print(f"baseline samples N = {N}; total events = {payload['baseline'].get('total')}")


def stats(rates):
    m = sum(rates) / len(rates)
    ci = 1.96 * math.sqrt(sum((x - m) ** 2 for x in rates) / len(rates)) / math.sqrt(len(rates))
    s = sorted(rates)
    return {"rate": m, "ci95": ci, "p05": s[len(s) // 20], "p50": s[len(s) // 2], "p95": s[len(s) - len(s) // 20 - 1]}


def run(ebpf_mode, drop=0.5, burst_len=20, seed=SEED):
    beta = 1.0 / burst_len
    alpha = beta  # keep stationary P(DROP)=0.5
    rng = random.Random(seed)
    p_drop = alpha / (alpha + beta)
    g1, g2, g3 = [], [], []
    for _ in range(NREP):
        state = 1 if rng.random() < p_drop else 0
        d1 = d2 = d3 = 0
        for _ in range(N):
            if ebpf_mode == "iid":
                ebpf_ok = rng.random() > drop
            else:  # markov bursty
                ebpf_ok = (state == 0)
            lsm_ok = rng.random() > LSM_DROP
            if ebpf_ok:
                d1 += 1
            if lsm_ok:
                d2 += 1
            if ebpf_ok or lsm_ok:
                d3 += 1
            if ebpf_mode == "markov":
                r = rng.random()
                state = 1 if (state == 0 and r < alpha) else (0 if (state == 1 and r < beta) else state)
        g1.append(d1 / N)
        g2.append(d2 / N)
        g3.append(d3 / N)
    return {"G1_eBPF_only": stats(g1), "G2_LSM_only": stats(g2), "G3_dual": stats(g3)}


out = {"seed": SEED, "N": N, "nrep": NREP, "lsm_drop": LSM_DROP, "runs": {}}

print("\nmode        L    drop  eBPF-only        LSM-only         Dual           (rates)")
r = run("iid", drop=0.5)
out["runs"]["iid_50"] = r
print(f"i.i.d.      -    0.50  {r['G1_eBPF_only']['rate']*100:6.2f}% [{r['G1_eBPF_only']['rate']*100 - r['G1_eBPF_only']['ci95']*100:.2f},{r['G1_eBPF_only']['rate']*100 + r['G1_eBPF_only']['ci95']*100:.2f}] "
      f"{r['G2_LSM_only']['rate']*100:6.2f}% [{r['G2_LSM_only']['rate']*100 - r['G2_LSM_only']['ci95']*100:.2f},{r['G2_LSM_only']['rate']*100 + r['G2_LSM_only']['ci95']*100:.2f}] "
      f"{r['G3_dual']['rate']*100:6.2f}% [{r['G3_dual']['rate']*100 - r['G3_dual']['ci95']*100:.2f},{r['G3_dual']['rate']*100 + r['G3_dual']['ci95']*100:.2f}]")

for L in (5, 20, 50):
    r = run("markov", drop=0.5, burst_len=L)
    out["runs"][f"bursty_L{L}"] = r
    print(f"bursty     {L:<3} 0.50  {r['G1_eBPF_only']['rate']*100:6.2f}% [{r['G1_eBPF_only']['rate']*100 - r['G1_eBPF_only']['ci95']*100:.2f},{r['G1_eBPF_only']['rate']*100 + r['G1_eBPF_only']['ci95']*100:.2f}] "
          f"{r['G2_LSM_only']['rate']*100:6.2f}% [{r['G2_LSM_only']['rate']*100 - r['G2_LSM_only']['ci95']*100:.2f},{r['G2_LSM_only']['rate']*100 + r['G2_LSM_only']['ci95']*100:.2f}] "
          f"{r['G3_dual']['rate']*100:6.2f}% [{r['G3_dual']['rate']*100 - r['G3_dual']['ci95']*100:.2f},{r['G3_dual']['rate']*100 + r['G3_dual']['ci95']*100:.2f}]")

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
print(f"\nwrote {OUT}")
