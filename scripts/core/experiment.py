"""Three-strategy comparison using actual Linux file permission results.

Verdict/delay are controlled factors, not measured LLM inference. This experiment
does not claim an eBPF observation or enforcement backend.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import errno
import hashlib
import json
from pathlib import Path
import platform
import random
import sys
import time

from core.bsigner import BSigner, BehaviorEvent
from core.governance import EvidenceVerifier, Governance, State, Strategy, python_risk_rule
from core.linux_dac import LinuxDACExecutor


class ExecutionMismatch(RuntimeError):
    """Failed positive controls and enforcement mismatches invalidate the trial."""


def perform(executor, governor, signer, verifier, op, name, payload="", phase="workload"):
    before = executor.size(name)
    result = executor.operation(op, name, payload)
    after = executor.size(name)
    permitted = (governor.permissions == "read-write" or
                 (governor.permissions == "read-only" and op == "read"))
    success = (result["ok"] and result["errno"] is None and
               result["bytes"] == (len(payload.encode()) if op == "append" else before))
    denied = (not result["ok"] and result["errno"] in (errno.EACCES, errno.EPERM)
              and result["bytes"] == 0 and after == before)
    effect_ok = after == before + (result["bytes"] if op == "append" and success else 0)
    if result["end_ns"] < result["start_ns"] or not effect_ok or not (success if permitted else denied):
        raise ExecutionMismatch("kernel result/side effect disagrees with policy: " + json.dumps({
            "state": governor.state.value, "permitted": permitted, "result": result,
            "before_size": before, "after_size": after}))
    event = BehaviorEvent(op, name, json.dumps(result, sort_keys=True, separators=(",", ":")))
    t_sign_start = time.monotonic_ns()
    seq = signer.seq_exp
    package = signer.verify_and_sign(event, signer.generate_channel_mac(event, seq), seq)
    t_sign_end = time.monotonic_ns()
    verified = verifier.accept(event, package)
    t_verify_end = time.monotonic_ns()
    record = dict(result, phase=phase, state=governor.state.value, state_version=governor.version,
                  permissions=governor.permissions, expected_allowed=permitted,
                  success=bool(success), denied=bool(denied), size_before=before, size_after=after,
                  sign_start_ns=t_sign_start, sign_end_ns=t_sign_end, verify_end_ns=t_verify_end,
                  event=asdict(event), evidence={"h_curr": package.h_curr.hex(), "seq": package.seq,
                    "sigma": package.sigma.hex(), "timestamp": package.timestamp, "version": package.version})
    return record, verified


def run_trial(strategy, scenario, jury_delay_ms, scoring_delay_ms, cooldown_ms=30,
              interval_ms=10, post_ms=60, executor_factory=LinuxDACExecutor):
    if scenario not in ("attack", "false_positive", "benign"):
        raise ValueError("unknown scenario")
    if min(jury_delay_ms, scoring_delay_ms, cooldown_ms, post_ms) < 0 or interval_ms <= 0:
        raise ValueError("invalid durations")
    signer = BSigner(did="trial-agent", node_id=platform.node(), container_id="linux-dac-worker")
    verifier = EvidenceVerifier("trial-agent", signer.get_public_key_bytes(), signer.get_h0())
    governor = Governance("trial-agent", strategy, int(cooldown_ms * 1e6))
    records, applications, times = [], [], {}
    with executor_factory() as executor:
        for op, name, payload in (("read", "diagnostic.txt", ""), ("append", "business.txt", "control|")):
            record, _ = perform(executor, governor, signer, verifier, op, name, payload, "control")
            records.append(record)
        trigger_name = "diagnostic.txt" if scenario == "benign" else "sensitive.txt"
        trigger, trigger_evidence = perform(executor, governor, signer, verifier, "read", trigger_name, phase="trigger")
        records.append(trigger)
        origin = trigger["start_ns"]
        times.update(trigger_start_ns=origin, trigger_end_ns=trigger["end_ns"],
                     trigger_verified_ns=trigger["verify_end_ns"])
        score_due = origin + int(scoring_delay_ms * 1e6)
        end_at = origin + int((scoring_delay_ms + jury_delay_ms + cooldown_ms + post_ms) * 1e6)
        next_op, verdict_due, scored = origin, None, False
        applied, operation_index = governor.permissions, 0
        while time.monotonic_ns() < end_at:
            now = time.monotonic_ns()
            if not scored and now >= score_due:
                times["score_start_ns"] = now
                suspicious = python_risk_rule(trigger_evidence)
                times["score_end_ns"] = time.monotonic_ns()
                scored = True
                if suspicious:
                    case = governor.open_case(trigger_evidence, times["score_end_ns"])
                    times["jury_start_ns"] = time.monotonic_ns()
                    verdict_due = times["jury_start_ns"] + int(jury_delay_ms * 1e6)
            now = time.monotonic_ns()
            if verdict_due is not None and now >= verdict_due:
                times["jury_end_ns"] = now
                governor.resolve(case, "guilty" if scenario == "attack" else "innocent", now)
                verdict_due = None
            governor.tick(time.monotonic_ns(), safe=True)
            if governor.permissions != applied:
                app = executor.apply(governor.permissions)
                app.update(state=governor.state.value, state_version=governor.version)
                applications.append(app)
                applied = governor.permissions
                if applied != "read-write":
                    times.setdefault("restriction_apply_end_ns", app["end_ns"])
                if applied == "deny-all":
                    times.setdefault("hard_apply_end_ns", app["end_ns"])
                if applied == "read-write":
                    times["restore_apply_end_ns"] = app["end_ns"]
            now = time.monotonic_ns()
            if now >= next_op:
                operations = [("read", "diagnostic.txt", ""),
                              ("append", "business.txt", "business-%d|" % operation_index)]
                if scenario == "attack":
                    operations.insert(0, ("append", "sink.txt", "attack-%d|" % operation_index))
                for op, name, payload in operations:
                    record, _ = perform(executor, governor, signer, verifier, op, name, payload)
                    records.append(record)
                    if record["denied"]:
                        times.setdefault("first_denial_observed_ns", record["end_ns"])
                    if name == "business.txt" and record["success"] and "restore_apply_end_ns" in times:
                        times.setdefault("first_restored_write_ns", record["end_ns"])
                operation_index += 1
                next_op = max(next_op + int(interval_ms * 1e6), time.monotonic_ns())
            wake = min(next_op, end_at)
            if not scored:
                wake = min(wake, score_due)
            if verdict_due is not None:
                wake = min(wake, verdict_due)
            if governor.safe_since is not None and governor.state == State.PROBATION:
                wake = min(wake, governor.safe_since + governor.cooldown_ns)
            pause = (wake - time.monotonic_ns()) / 1e9
            if pause > 0:
                time.sleep(pause)
        work = [r for r in records if r["phase"] == "workload"]
        danger = [r for r in work if r["name"] == "sink.txt"]
        business = [r for r in work if r["name"] == "business.txt"]
        reads = [r for r in work if r["op"] == "read"]
        successful_bytes = sum(r["bytes"] for r in danger if r["success"])
        if executor.size("sink.txt") != successful_bytes:
            raise ExecutionMismatch("sink contents do not match successful operations")
        if not scored or (scenario != "benign" and "jury_end_ns" not in times):
            raise ExecutionMismatch("horizon ended before verdict; increase post_ms")
    def since(key):
        return (times[key] - origin) / 1e6 if key in times else None
    return {"strategy": Strategy(strategy).value, "scenario": scenario,
            "jury_delay_ms": jury_delay_ms, "scoring_delay_ms": scoring_delay_ms,
            "cooldown_ms": cooldown_ms, "interval_ms": interval_ms, "post_ms": post_ms,
            "valid": True, "final_state": governor.state.value,
            "public_key": signer.get_public_key_bytes().hex(), "anchor": signer.get_h0().hex(),
            "times_ns": times, "applications": applications, "transitions": governor.transitions,
            "metrics": {
                "danger_attempts": len(danger), "danger_successes": sum(r["success"] for r in danger),
                "danger_denied": sum(r["denied"] for r in danger), "danger_bytes": successful_bytes,
                "business_attempts": len(business), "business_successes": sum(r["success"] for r in business),
                "business_denied": sum(r["denied"] for r in business),
                "read_attempts": len(reads), "read_successes": sum(r["success"] for r in reads),
                "restriction_apply_ms": since("restriction_apply_end_ns"),
                "first_denial_ms": since("first_denial_observed_ns"),
                "hard_apply_ms": since("hard_apply_end_ns"),
                "recovery_from_trigger_ms": since("first_restored_write_ns"),
                "recovery_after_verdict_ms": ((times["first_restored_write_ns"] - times["jury_end_ns"]) / 1e6
                                              if "first_restored_write_ns" in times else None),
                "verified_events": verifier.next_seq}, "operations": records}


def summarize(trials):
    import numpy as np
    groups = {}
    for trial in trials:
        key = (trial["scenario"], trial["scoring_delay_ms"], trial["jury_delay_ms"], trial["strategy"])
        groups.setdefault(key, []).append(trial)
    rows = []
    for (scenario, scoring, jury, strategy), group in sorted(groups.items()):
        metrics = [r["metrics"] for r in group]
        row = dict(scenario=scenario, scoring_delay_ms=scoring, jury_delay_ms=jury, strategy=strategy, n=len(group))
        for key in ("danger_attempts", "danger_successes", "danger_denied", "danger_bytes",
                    "business_attempts", "business_successes", "business_denied", "read_attempts", "read_successes"):
            row[key] = sum(m[key] for m in metrics)
        row["business_success_rate"] = row["business_successes"] / row["business_attempts"]
        row["read_success_rate"] = row["read_successes"] / row["read_attempts"]
        for key in ("restriction_apply_ms", "first_denial_ms", "hard_apply_ms", "recovery_from_trigger_ms", "recovery_after_verdict_ms"):
            values = [m[key] for m in metrics if m[key] is not None]
            row[key] = {"n": len(values), "p50": float(np.median(values)),
                        "p95": float(np.percentile(values, 95))} if values else None
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=10)
    parser.add_argument("--jury-delay-ms", default="50,200")
    parser.add_argument("--scoring-delay-ms", default="0,50")
    parser.add_argument("--cooldown-ms", type=float, default=30)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed", type=int, default=20261026)
    args = parser.parse_args()
    if args.n < 1:
        parser.error("--n must be positive")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output_dir or Path("results") / ("revalidated_linux_dac_" + stamp)
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    source = [root / "end_to_end_e2e.py", *sorted((root / "core").glob("*.py"))]
    metadata = {"schema": "ertb-operation-experiment-v2", "started_utc": stamp,
        "backend": "Linux DAC; root controller; uid/gid 65534 worker; fresh-open file operations",
        "observation": "trusted worker/controller instrumentation, not eBPF",
        "jury": "controlled fixture oracle + scheduled delay, no LLM inference",
        "clock": "time.monotonic_ns across processes on the same Linux host",
        "platform": platform.platform(), "python": sys.version, "seed": args.seed,
        "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source},
        "status": "running", "n_per_cell": args.n}
    meta_path = output / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    tasks = [(s, c, j, d) for _ in range(args.n) for c in ("attack", "false_positive", "benign")
             for j in map(float, args.jury_delay_ms.split(","))
             for d in map(float, args.scoring_delay_ms.split(",")) for s in Strategy]
    random.Random(args.seed).shuffle(tasks)
    trials, raw_path = [], output / "trials.jsonl"
    try:
        with raw_path.open("w", encoding="utf-8") as raw:
            for index, (strategy, scenario, jury, scoring) in enumerate(tasks, 1):
                trial = run_trial(strategy, scenario, jury, scoring, args.cooldown_ms)
                trial["trial_id"] = index
                raw.write(json.dumps(trial, ensure_ascii=False) + "\n")
                raw.flush()
                trials.append(trial)
                if index % 10 == 0 or index == len(tasks):
                    print("Completed %d/%d actual-operation trials" % (index, len(tasks)), flush=True)
        (output / "summary.json").write_text(json.dumps(summarize(trials), indent=2), encoding="utf-8")
        metadata.update(status="complete", completed_trials=len(trials), raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest())
    except Exception as exc:
        metadata.update(status="failed", completed_trials=len(trials), error=repr(exc))
        raise
    finally:
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print("Results:", output.resolve(), flush=True)
