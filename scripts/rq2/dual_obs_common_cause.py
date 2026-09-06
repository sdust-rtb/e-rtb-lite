"""
Common-cause (correlated) observation-loss extension of the dual-observation
experiment.

The bursty-loss study (rq2/dual_obs_bursty.py) shows that CONSECUTIVE (Markov)
eBPF drops do not hurt the dual path, because the intact LSM path dominates the
union. That conclusion is conditional on the STRUCTURAL-INDEPENDENCE assumption:
eBPF and LSM fail independently of each other. This script closes that gap by
adding a COMMON-CAUSE outage layer that silences BOTH observation paths in the
same window -- the failure mode a reviewer is entitled to ask about (host CPU
saturation / scheduler stall, container pause or live migration, kernel audit
ring stall, the Unix-socket path between the observation module and the signer
going down, host reboot).

Model (pure post-processing over the SAME 10,000-event baseline sample used by
ebpf_runner.py / dual_obs_bursty.py; no kernel, no cloud, no API):

    host-level two-state chain  NORMAL <-> OUTAGE
      OUTAGE  : both channels silent (drop probability 1 for eBPF and for LSM)
      NORMAL  : per-channel independent loss, eBPF drop = EBPF_DROP,
                LSM drop = LSM_DROP

Two families of common-cause schedules are compared:
  (a) i.i.d. (Bernoulli) OUTAGE windows at a mean outage fraction p_cc, and
  (b) bursty (Markov) OUTAGE windows at a fixed p_cc with mean outage run
      length L, i.e. correlated in time (the realistic multi-second stall case).

Per configuration we report: detection rate, 95% CI, p05/p50/p95 over the
n=100 repeats, the eBPF/LSM marginal drop rates, the eBPF<->LSM drop-indicator
correlation (0 under structural independence), and p_cc_hat, the common-cause
fraction inferred back from the measured dual rate alone.

Because the outage layer multiplies every channel by (1 - p_cc), the model has
a closed form that the simulation is checked against:

    rate_dual(p_cc)            = (1 - p_cc) * U
    rate_dual(p_cc) - rate_ebpf(p_cc) = (1 - p_cc) * (U - C_ebpf)

where U is the union coverage measured at p_cc = 0.

Output: results/rq2_dual_obs_common_cause.json
"""
import json
import math
import random
from pathlib import Path

HERE = Path(r"D:\data\RTB\experiments")
DATA = HERE / "results" / "rq2_real_dual_obs.json"
OUT = HERE / "results" / "rq2_dual_obs_common_cause.json"

EBPF_DROP = 0.50         # per-event eBPF loss inside NORMAL (paper's 50% case)
LSM_DROP = 0.01          # per-event LSM loss inside NORMAL (matches the original)
NREP = 100               # repeats (matches the original)
SEED = 20260905          # recorded for reproducibility
IID_PCC = (0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20)
BURST_PCC = (0.01, 0.05)
BURST_L = (5, 20, 50)
TARGETS = (0.99, 0.95)

payload = json.load(open(DATA, encoding="utf-8"))
samples = payload["baseline"]["samples"]
N = len(samples)
print(f"baseline samples N = {N}; baseline total events = {payload['baseline'].get('total')}")


def stats(rates):
    m = sum(rates) / len(rates)
    ci = 1.96 * math.sqrt(sum((x - m) ** 2 for x in rates) / len(rates)) / math.sqrt(len(rates))
    s = sorted(rates)
    return {"rate": m, "ci95": ci, "p05": s[len(s) // 20], "p50": s[len(s) // 2], "p95": s[len(s) - len(s) // 2 - 1]}


def run(p_cc, mode="iid", burst_len=20, seed=SEED):
    """Simulate one common-cause schedule over the shared baseline sample.

    mode 'iid':    OUTAGE is an independent Bernoulli(p_cc) per event.
    mode 'markov': OUTAGE is a two-state chain with stationary P(OUTAGE)=p_cc
                   and mean outage-run length = burst_len.
    """
    if p_cc <= 0.0:
        no_outage = True
        beta = 0.0
        alpha = 0.0
        p_out = 0.0
    else:
        no_outage = False
        beta = p_cc if mode == "iid" else 1.0 / burst_len
        alpha = p_cc * beta / (1.0 - p_cc) if p_cc < 1.0 else 1.0
        p_out = alpha / (alpha + beta)
    rng = random.Random(seed)

    r1, r2, r3 = [], [], []
    sum_e = sum_l = sum_el = 0          # for the exact drop-indicator correlation
    for _ in range(NREP):
        state = 0 if no_outage else (1 if rng.random() < p_out else 0)
        ok1 = ok2 = ok3 = 0
        for _ in range(N):
            if state == 1:                                   # common-cause outage
                ebpf_ok = False
                lsm_ok = False
            else:                                            # structurally independent
                ebpf_ok = rng.random() > EBPF_DROP
                lsm_ok = rng.random() > LSM_DROP
            if ebpf_ok:
                ok1 += 1
            if lsm_ok:
                ok2 += 1
            if ebpf_ok or lsm_ok:
                ok3 += 1
            de = 1 - int(ebpf_ok)
            dl = 1 - int(lsm_ok)
            sum_e += de
            sum_l += dl
            sum_el += de * dl
            if not no_outage:
                r = rng.random()
                state = 1 if (state == 0 and r < alpha) else (0 if (state == 1 and r < beta) else state)
        r1.append(ok1 / N)
        r2.append(ok2 / N)
        r3.append(ok3 / N)

    ntot = NREP * N
    me = sum_e / ntot
    ml = sum_l / ntot
    cov = sum_el / ntot - me * ml
    corr = None
    if me > 0 and me < 1 and ml > 0 and ml < 1:
        corr = cov / math.sqrt(me * (1 - me) * ml * (1 - ml))
    return {
        "G1_eBPF_only": stats(r1),
        "G2_LSM_only": stats(r2),
        "G3_dual": stats(r3),
        "ebpf_drop_rate": me,
        "lsm_drop_rate": ml,
        "drop_indicator_correlation": corr,
    }


out = {
    "metadata": {
        "seed": SEED,
        "N": N,
        "nrep": NREP,
        "ebpf_drop_in_normal": EBPF_DROP,
        "lsm_drop_in_normal": LSM_DROP,
        "model": "host-level common-cause OUTAGE layer silences both channels; channels independent inside NORMAL",
        "ci": "normal approximation over the 100 repeats (identical to the original dual-obs experiment)",
    },
    "runs": {},
}

# ---- reference run: p_cc = 0 must reproduce the published 50% case ----------
ref = run(0.0, mode="iid")
ref["p_cc"] = 0.0
ref["mode"] = "iid"
out["runs"]["independent_baseline"] = ref
U = ref["G3_dual"]["rate"]
C_ebpf = ref["G1_eBPF_only"]["rate"]
C_lsm = ref["G2_LSM_only"]["rate"]
out["metadata"].update({
    "U_union_coverage_at_zero_common_cause": U,
    "ebpf_only_coverage_at_zero_common_cause": C_ebpf,
    "lsm_only_coverage_at_zero_common_cause": C_lsm,
})
print(f"\nreference (p_cc = 0, structurally independent paths):")
print(f"  eBPF-only {C_ebpf*100:.2f}%   LSM-only {C_lsm*100:.2f}%   dual {U*100:.2f}%")
print(f"  (paper / Table 10 report 50.02% / 99.00% / 99.49%)\n")

print("schedule     p_cc    L    eBPF-only     LSM-only        Dual       dual FN    rho(eBPF,LSM)  sim-closedform")
for p_cc in IID_PCC:
    r = run(p_cc, mode="iid")
    r["p_cc"] = p_cc
    r["mode"] = "iid"
    r["analytical_ebpf"] = (1 - p_cc) * C_ebpf
    r["analytical_lsm"] = (1 - p_cc) * C_lsm
    r["analytical_dual"] = (1 - p_cc) * U
    r["analytical_delta_dual"] = r["G3_dual"]["rate"] - (1 - p_cc) * U
    r["p_cc_hat_from_dual_rate"] = 1.0 - r["G3_dual"]["rate"] / U
    out["runs"][f"common_cause_iid_pcc_{int(round(p_cc*1000)):04d}"] = r
    rho = r["drop_indicator_correlation"]
    print(f"iid          {p_cc:<6}  -    {r['G1_eBPF_only']['rate']*100:7.3f}%    {r['G2_LSM_only']['rate']*100:7.3f}%    "
          f"{r['G3_dual']['rate']*100:7.3f}%    {(1-r['G3_dual']['rate'])*100:6.3f}%    "
          f"{rho if rho is not None else float('nan'):9.4f}    {r['analytical_delta_dual']*100:+7.3f} pp")

for p_cc in BURST_PCC:
    for L in BURST_L:
        r = run(p_cc, mode="markov", burst_len=L)
        r["p_cc"] = p_cc
        r["mode"] = "markov"
        r["mean_outage_run"] = L
        r["analytical_ebpf"] = (1 - p_cc) * C_ebpf
        r["analytical_lsm"] = (1 - p_cc) * C_lsm
        r["analytical_dual"] = (1 - p_cc) * U
        r["analytical_delta_dual"] = r["G3_dual"]["rate"] - (1 - p_cc) * U
        r["p_cc_hat_from_dual_rate"] = 1.0 - r["G3_dual"]["rate"] / U
        out["runs"][f"common_cause_bursty_pcc_{int(round(p_cc*1000)):04d}_L{L}"] = r
        rho = r["drop_indicator_correlation"]
        print(f"bursty       {p_cc:<6} {L:<4} {r['G1_eBPF_only']['rate']*100:7.3f}%    {r['G2_LSM_only']['rate']*100:7.3f}%    "
              f"{r['G3_dual']['rate']*100:7.3f}%    {(1-r['G3_dual']['rate'])*100:6.3f}%    "
              f"{rho if rho is not None else float('nan'):9.4f}    {r['analytical_delta_dual']*100:+7.3f} pp")

# ---- coverage targets: max tolerable common-cause fraction -----------------
targets = {}
for t in TARGETS:
    max_pcc = 1.0 - t / U
    ok_runs = [n for n, rr in out["runs"].items() if rr.get("mode") == "iid" and rr["G3_dual"]["rate"] >= t]
    targets[f"dual_ge_{int(t*100)}pct"] = {
        "target_detection_rate": t,
        "max_p_cc_analytical": max_pcc,
        "max_p_cc_pct": max_pcc * 100,
        "simulated_runs_meeting_target": ok_runs,
    }
out["coverage_targets"] = targets
out["formula"] = {
    "rate_dual": "rate_dual(p_cc) = (1 - p_cc) * U,  U = union coverage measured at p_cc = 0",
    "redundancy_gain": "gain_over_eBPF(p_cc) = (1 - p_cc) * (U - C_ebpf)",
    "self_diagnostic": "p_cc_hat = 1 - rate_dual / U",
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)

print(f"\ncoverage targets (dual-path detection must stay >= target):")
for k, v in targets.items():
    print(f"  {k}: max common-cause fraction = {v['max_p_cc_pct']:.3f}%")
print(f"\nwrote {OUT}")
