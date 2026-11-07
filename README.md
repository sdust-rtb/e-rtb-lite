# E-RTB Lite — Reproducibility Artifact

**Paper:** Runtime Permission Governance for Autonomous Agents under Delayed Adjudication (target: CCPE)
Per-trial records for §6.3–6.9 are shipped as Supporting Information S1 (archive/); this repository holds the verifiers, manifest and claim ledger. See VERIFY.md for the repo/archive split.

This artifact contains the data, scripts, prompts, and configuration needed to reproduce the experiments reported in the paper. A machine-readable experiment index is in [`ARTIFACT_MANIFEST.json`](ARTIFACT_MANIFEST.json).

**Verification entry point:** [`VERIFY.md`](VERIFY.md) lists, per study, which file verifies which number and which command regenerates the check, together with the studies whose artefacts are *not* in this repository and the gaps that remain open. Per-claim status is in [`audit/verification/claim_ledger.json`](audit/verification/claim_ledger.json).

> **Scope reminder.** E-RTB Lite is a **single-node engineering prototype**. Several results are **simulations** (loss-tolerance, dynamics, ablation, resilience, dynamic-ρ loop) that are pure post-processing on captured baseline data and need no kernel/cloud; others are **real** measurements (forgery, LLM jury, e2e, benchmarks, cross-node feasibility). See `simulation_vs_real` in the manifest.

## Directory layout

| Path | Contents |
|------|----------|
| `ARTIFACT_MANIFEST.json` | Machine-readable index: each experiment → scripts, raw output, seed, paper section/table/figure, environment, hardware requirements |
| `configs/` | Jury system prompt, user-prompt template, and the deterministic Rego violation-pattern set |
| `data/` | 180-case arbitration dataset (+240 pool), synthetic behavior events, collusion pairs, raw observation entries |
| `results/` | Raw JSON outputs for every experiment (RQ1–RQ4, dual-obs + bursty + common-cause, single-juror, cross-node, e2e) |
| `scripts/` | Experiment drivers: `core/` (bsigner, data_gen), `rq1/`–`rq4/`, cross-node, e2e |
| `figures/` | Figure-generation scripts (Fig 4 TikZ source, Fig 6/7/8/9 generators) |
| `requirements.txt` | Python dependencies |

## Environment

- **Local dev / CPU experiments:** x86_64, Python 3.9 (repo bytecode is cpython-39).
- **eBPF experiments:** Linux host, **root + BCC**, Kernel ≥ 5.15 (Ubuntu 22.04 used).
- **LLM (jury / e2e) experiments:** **NVIDIA A40, ≥ 48 GB** GPU memory, **vLLM v0.20.1**, serving `Qwen/Qwen2.5-3B-Instruct` and `THUDM/glm-4-9b-chat`; `DeepSeek-V3.2` via API for the without-Rego ablation. Decoding is **temperature = 0** (greedy) for deterministic verdicts; the homogeneous baseline uses temperature perturbation to break determinism.

## Quick start

```bash
pip install -r requirements.txt

# 1. Data generation (deterministic, seed 42)
python scripts/core/data_gen.py

# 2. CPU experiments (no special hardware)
python scripts/rq1/attack_simulator.py        # 300K forgery
python scripts/rq3/micro_benchmark.py         # component benchmark
python scripts/rq3/stress_test.py             # concurrent signer
python scripts/rq3/dct_vs_jwt.py              # credential ablation

# 3. Dual-observation (simulation on the captured baseline; no kernel needed)
python scripts/rq2/dual_obs_bursty.py          # uniform + bursty eBPF loss, seed 20260905
python scripts/rq2/dual_obs_common_cause.py    # common-cause (correlated) outage layer, seed 20260905

# 4. Jury quality (needs A40 + vLLM endpoints; see scripts/rq2/jury_quality.py)
python scripts/rq2/jury_quality.py
python scripts/rq2/single_juror_stats.py       # per-auditor error rates (post-processing, no GPU)

# 5. Regenerate figures
python figures/gen_fig11.py                   # Figure 7
python figures/regenerate_fig6_dual_obs.py    # Figure 6
```

The eBPF capture that feeds the dual-observation baseline is produced by `scripts/rq2/ebpf_runner.py` on the Linux host (`sudo python scripts/rq2/ebpf_runner.py 60 --dual-obs`); the captured baseline is committed in `results/rq2_real_dual_obs_baseline.json` so the loss-tolerance evaluation can be reproduced without re-capture.

## Random seeds

| Experiment | Seed |
|------------|------|
| Data generation | 42 |
| Cross-node rounds (N=30) | 42 + i, i = 0..29 |
| Figure generation | 42 |
| Dual-obs bursty loss | 20260905 |
| Dual-obs common-cause outage layer | 20260905 |
| Single-juror error rates | deterministic post-processing (no RNG) |
| Dual-obs original uniform loss | **not seeded** (known reproducibility gap — see paper Limitations) |
| bsigner key derivation | `os.urandom(32)` (non-deterministic by design; key material is not committed) |

## What is and is not included

- **Included:** all experiment scripts, raw JSON results, the 180-case dataset, jury prompts, Rego rules, figure generators, environment/seed documentation.
- **Not included (by design):** signer private keys and channel keys (secret material); the A40 model weights (use the public Hugging Face checkpoints listed in `environment.models`); the raw multi-GB eBPF capture archives (a 10,000-event sample is committed in the baseline JSON).
- **Model versions:** `Qwen2.5-3B-Instruct`, `GLM-4-9B-Chat` (public checkpoints); `DeepSeek-V3.2` (API). Pin these for exact reproduction.

## Known limitations carried into the paper

- The dual-observation loss-tolerance result is a **simulation** over the per-event baseline sample (uniform, bursty, and common-cause), not a physical re-capture under induced kernel loss. The common-cause case (`scripts/rq2/dual_obs_common_cause.py`) is quantified rather than ignored: dual-path detection degrades as `rate_dual = (1 - p_cc) * U`, so a shared-infrastructure outage that silences both paths in the same window is **not** covered by the redundancy claim — holding detection ≥ 99% requires `p_cc ≤ 0.50%`.
- The dynamic ρ control loop / juror replacement is **simulation-only**.
- Cross-node is a **feasibility** measurement (controlled 10 ms simulated one-way delay, one-way path), not a replicated multi-node deployment.
- Systematic fault-injection and a quantitative Falco+OPA+SPIFFE head-to-head are **future work**.
