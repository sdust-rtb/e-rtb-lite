# Core repairs and actual-operation revalidation (2026-10-26)

This experiment replaces the old `end_to_end_e2e.py` accounting harness. Historical
result files are preserved; they do not become measurements of the new protocol.
The pre-repair driver and core are archived under
`D:\data\RTB\audits\2026-10-26-core-timing\before-repair`.

## What is implemented

- An isolated Linux temporary directory owned by the root controller. A subprocess
  drops supplementary groups and runs with UID/GID 65534. It performs real reads
  and append writes, opening and closing each file on every command.
- The controller applies Linux DAC modes to fixture files: Active = read/write,
  Probation and Pending-Arbitration = read only, Revoked = deny all. The worker
  cannot change these root-owned files' modes or create/replace directory entries.
- Every attempted workload operation is dispatched even if policy says deny. A
  denied operation must return EACCES/EPERM and leave file size unchanged. Successful
  writes must add the requested bytes. Unexpected denial or success invalidates
  the trial; no-op enforcement is covered by a failing negative-control test.
- The controller signs each observed operation result. Before the policy consumes
  an event, a separate verifier checks signature, exact sequence, and event-to-chain
  linkage against a provisioned agent key/anchor. Invalid input does not advance
  verifier state. Replay, modified fields, changed timestamps and wrong anchors
  are tested. Canonical v2 JSON encoding fixes the delimiter collision.
- Decisions reference the verified triggering chain hash and a policy version.
  Pending cannot recover before a valid verdict. Failure/abstention retains the
  pending restriction. Innocent verdicts start a consecutive-safe cooldown;
  Revoked is terminal. The wait-for-verdict baseline deliberately remains Active
  with an open case, rather than mislabeling unrestricted access as Pending.
- All elapsed times use `time.monotonic_ns()` on the same Linux host. The trace
  preserves operation, signing, verification, scoring, policy-application,
  verdict, observed denial and recovery timestamps separately.

## Explicit limits

This is **Linux DAC file-access enforcement**, not eBPF enforcement, not a
container-level syscall monitor, and not a general agent sandbox. It does not
revoke already-open descriptors and does not cover sockets, exec, or arbitrary
agent actions. The controlled worker issues only allowlisted commands. The
kernel, controller, worker instrumentation and cryptographic runtime are trusted.
The event stream is instrumented at the application boundary, not independently
captured in the kernel. State is in memory; crash persistence and distributed
authorization are not implemented by this experiment.

The jury is a **controlled fixture oracle** with configured delay. Attack fixtures
receive guilty, false-positive fixtures innocent; no LLM is called. These results
measure enforcement/availability tradeoffs conditional on that verdict, not judge
accuracy or LLM inference latency. The risk rule is Python, not OPA/Rego.

The alert is triggered by a real successful read of a fixture sensitive file.
That initial read is not prevented. Subsequent designated dangerous operations
are append writes to a fixture sink; benign work includes diagnostic reads and
business-file writes. No real secret files or external network destinations are
accessed. The benign-no-alert control reads a diagnostic fixture instead.

Configured scoring delay is an eligibility delay from the triggering operation's
start, while operations continue. It is not a claim that a periodic production
scheduler was deployed. Measured times include signing, IPC and scheduling jitter.
Policy-application end and first observed denied operation are distinct. Attempt
frequency is nominally 10 ms; delayed cycles do not generate catch-up bursts, so
report actual attempt counts/rates as well as successes.

## Reproduce

Use Linux Python with `cryptography`, `numpy`, and `pytest`; `matplotlib` is needed
for the legacy state-ablation regression. Run from the experiment root as root
only to set up the separate-UID worker. The worker itself is unprivileged.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 python3 end_to_end_e2e.py \
  --n 20 --jury-delay-ms 50,200 --scoring-delay-ms 0,50 \
  --output-dir results/revalidated_linux_dac_NEW_RUN
python3 scripts/verify_operation_results.py results/revalidated_linux_dac_NEW_RUN
```

Each new output directory must not already exist. The default matrix contains
3 strategies × 3 scenarios × 2 scoring delays × 2 verdict delays × 20 repeats =
720 trials, shuffled with seed 20261026. Setup and worker startup are excluded
from response timing but performed afresh per trial. Positive read/write controls
run before the trigger. Each cell uses the same observation horizon.

Outputs:

- `metadata.json`: platform, source hashes, clock, explicit measurement boundary,
  completion/failure status and raw-file hash.
- `trials.jsonl`: every operation outcome and side-effect sizes, complete signed
  event/package, timestamps, state transitions, actual counts, configuration and
  per-trial metrics. Public verification keys only; no private/channel keys.
- `summary.json`: cell-wise counts, observed availability and P50/P95 computed
  from the per-trial raw measurements. Missing recovery/denial remains null.

`scripts/verify_operation_results.py` independently replays every evidence chain,
checks signed outcomes against reported results, checks side effects, recomputes
counts/timing and rejects a pending write success. It does not manufacture missing
historical samples or validate the old e2e files.

## Historical scope

The old 929.6 ms result, 0.129 ms trigger statistic, OPA/Rego labels, cross-node
driver, credential ablation and checkpoint timings retain the caveats in the
audit report. This change does not silently fix or validate those other studies.
The numerical state ablation is updated to explicit pending state J and consecutive
safe-step cooling; old saved trajectories must not be presented as regenerated
v2 outputs. The v2 event encoding and signature domain intentionally change the
wire protocol; old evidence is not silently accepted by the v2 verifier.
