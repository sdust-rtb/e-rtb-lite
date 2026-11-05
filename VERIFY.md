# Verification entry point

This file states, per study, **which file verifies which number** and **which command regenerates the check**. It also states plainly what this repository does *not* contain, so that a reader does not mistake an absence for a passing check.

> **Section numbering.** All `§x.y` references below are to the current revised manuscript, *Runtime Permission Governance for Autonomous Agents under Delayed Adjudication* (target CCPE), in which Section 5 is the Experimental Evaluation (5.1 Evidence Integrity, 5.2 Controlled Permission Restriction and Recovery, 5.3 Scoped Recovery, 5.4 VM BPF-LSM, 5.5 Ruling Quality, 5.6 AgentHarm, 5.7 Capability-Matched Reference, 5.8 Credential Design Ablation, 5.9 Live-Agent Adjudication).

Paths are relative to the archive root they belong to:

- `repo/` — this repository (`e-rtb-lite`).
- `archive/` — the experiment tree shipped with the submission (`experiments/` and `audits/`), which is not part of the public repository because it contains VMware images, root-level BPF-LSM runs, and API-calling live-agent logs.

Nothing in this file asserts that every result in the paper has been independently replayed. The per-entry status is in the claim ledger (`audit/verification/claim_ledger.json`, 95 entries).

---

## A. Studies whose artefacts are in this repository

| Paper result | Data | Verifier | Command |
|---|---|---|---|
| §5.1 forgery (legacy signer campaign), 300,000 trials | `results/rq1_attack_results.json` | `audit/recompute.py` | `python audit/recompute.py` |
| §5.8 credential/evidence acceptance (v2) | `results/credential_v2_20261026/` | `scripts/scripts/verify_credential_results.py` | `python scripts/scripts/verify_credential_results.py` |
| §5.2 Linux DAC, 720 trials, 42,480 records | `results/revalidated_linux_dac_20261026/` | `scripts/scripts/verify_operation_results.py` | `python scripts/scripts/verify_operation_results.py` |
| §5.5 ruling quality, 180 cases | `results/rq2_ambiguous_consensus.json`, `data/` | `audit/recompute.py` | `python audit/recompute.py` |
| §5.6 AgentHarm clustering | `results/agentharm_jury_api.json` | `archive/audits/2026-11-03-verification/verify_agentharm_cluster.py` | `python audits/2026-11-03-verification/verify_agentharm_cluster.py` (from `archive/`) |

Both shipped verifiers enforce a **source-hash gate**: they recompute SHA-256 over the recorded input files and abort if a file has drifted. Their pass/fail output therefore covers provenance and data checks separately, and neither is a claim about the whole archive.

`scripts/verify_property3.py` checks Property 3 numerically; it is a property check, not a result verifier.

## B. Studies in the archived experiment tree

Run from `archive/`:

| Paper result | Data | Verifier | Command |
|---|---|---|---|
| §5.2 matched recovery cooldown | `experiments/results/recovery_fair_20261026/` | none — see gaps | — |
| §5.3 scoped workflow (WSL2/VMware) | `experiments/results/scoped_workflow_*` | inside the run's `verify_*.py` | `python experiments/.../verify_scoped_workflow.py` |
| §5.4 VM BPF-LSM | `experiments/results/vm_bpf_scoped_20261028/` | inside the run's verifier | as recorded in the run's `metadata.json` |
| §5.2 concurrent cases, 80 trials + 40 negative controls | `experiments/results/concurrent_case_executor_20261028*/` | `audits/2026-11-03-verification/verify_concurrency_logic.py`, `verify_invariant_J.py` | `python audits/2026-11-03-verification/verify_invariant_J.py` |
| §5.7 capability-matched (outcome parity + cost) | `experiments/results/fair_baseline_vm_20261028/matched_final/` | `experiments/fair_bpf_baseline/verify_fair_workload.py`, driven by `audits/2026-11-03-verification/verify_fair_bpf_nogate.py` | `python audits/2026-11-03-verification/verify_fair_bpf_nogate.py` |
| §5.7 identity binding, 120 trials | `experiments/results/identity_binding_vm_formal_final2_20261028/` | the run's own `verify_identity_binding.py` (passes 120/120 against `trials_sha256`) | `cd experiments/results/identity_binding_vm_formal_final2_20261028 && python verify_identity_binding.py` |
| §5.9 live agent | `experiments/results/agent_react_loop_20261029_*/` | `audits/2026-11-03-verification/verify_live_agent_replay.py` (recomputes denials, completion and transition invariants from each trial's step log) | `python audits/2026-11-03-verification/verify_live_agent_replay.py` |

`verify_fair_bpf_nogate.py` neutralises **only** `verify_source_bundle` and prints the two statuses separately, because four harness files in that experiment cannot be restored to their recorded hashes (see gaps). It is a data check, not a provenance pass.

## C. Claim ledger

`audit/verification/claim_ledger.json` holds one record per claim:

```json
{"id": "I-fp10-scoped", "paper": "on-time tasks, fp10 (E-RTB)",
 "declared": 33, "recomputed": 33,
 "source": "matched_final/fp10/summary.json", "status": "PASS", "basis": "summary"}
```

`basis` distinguishes `raw` (records re-read), `raw-verifier` (a shipped verifier was run), `summary` (a recorded aggregate was re-read, not recomputed), and `aggregate-pending` (grouped from saved outputs, no replay).

Totals across the 95 entries — by basis: 17 `raw`, 3 `raw-verifier`, 71 `summary`, 4 `none` (retired); by status: 91 `PASS`, 4 `RETIRED`, 0 `MISMATCH`.

The four retired entries are claims the paper no longer makes: three batch-signing numbers that survive only as terminal transcripts, and one live-agent recovery interval that cannot be recomputed because the step logs carry no timestamps.

A `summary` basis means the number agrees with the shipped summary; it is **not** a recomputation from per-trial records. Ledger agreement must not be reported as full recomputation.

## D. Gaps — stated, not worked around

1. **Four harness files cannot be restored.** `run_fair_race_bpf.py`, `scoped_workflow_experiment.py`, `bench_opa_workload_bpf.py`, and `core/independent_evidence.py` differ from their recorded SHA-256 in `experiments/results/fair_baseline_vm_20261028/` and no matching copy exists in the archive or in git history. Recorded hashes were not edited.
2. **`results_formal_{late,early,tight,fp10,fp25}_20261028` fail the current checks** and are retained as history only: 16 of 20 recorded files match, and 80 of 100 rows per run carry `credential: null` because only the baseline arm signed, which raises `TypeError` in the shipped verifier. No number in the paper comes from these directories.
3. **`recovery_fair_20261026` has no verifier** and no `raw_sha256`/`verification.json`; its numbers rest on the run's own summary.
4. **Batch signing (113,559 events, 7.026 s)** survives only as terminal transcripts and code excerpts; no machine-readable record remains.
5. **The test suite is not green.** `pytest scripts/tests` reports two failures in `rq4.state_ablation`, a module that imports only `os`/`json`/`numpy`/`matplotlib` and is unrelated to the reported results. The same failures occur on a pre-fix copy, so they predate the package repair.
6. **Live-agent cells are replayed from step logs, not from signatures.** `verify_live_agent_replay.py` recomputes denial counts, completion and transition-chain invariants for all 18 cells (18/18 agree with the recorded summaries; 630 per-trial checks pass). Signature and HMAC replay is impossible because channel keys are excluded from the package, and `recovery_ms` cannot be recomputed because the step log has no timestamps. The recorded security/availability split follows a per-scenario convention: in an attack trial every denial counts as a security block; in a false-alarm trial only denials of non-flagged resources count as availability loss, so the two columns need not sum to the denial total.

## E. Identifiers

- The authoritative per-run identifier is `source_sha256` inside each run's `metadata.json`: it pins the code that produced that run, which is what the shipped verifiers check. Where a run also has `verification.json`, it carries a hash over the trial records (`trials_sha256`).
- The verification record for this revision is `audits/2026-11-03-verification/` (verifier scripts, `out/claim_ledger.json`, `PRESUBMISSION_CHECK_20261103.md`).
- This file and `audit/verification/` postdate tag `v1.0.0`; a tag for the submitted revision should be cut when the package is frozen, since a repository tag is only meaningful once the file it names is committed.
