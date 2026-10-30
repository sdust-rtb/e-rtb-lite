"""Real-clock, controlled races through the Linux DAC actuator.

Run in Linux as root. Every case is opened from a signed, verified event.
The worker uses fresh file opens as uid 65534. This experiment checks the
actuator result and file side effect, not just the controller state.
"""
import argparse
import errno
import hashlib
import json
from pathlib import Path
import random
import statistics
import threading
import time

from core.bsigner import BSigner, BehaviorEvent
from core.governance import EvidenceVerifier, Governance, State, Strategy
from core.linux_dac import LinuxDACExecutor


def signed_case(signer, verifier, governor, label):
    event = BehaviorEvent("read", "sensitive.txt", json.dumps({"case": label, "ok": True}))
    seq = signer.seq_exp
    package = signer.verify_and_sign(event, signer.generate_channel_mac(event, seq), seq)
    verified = verifier.accept(event, package)
    return governor.open_case(verified, time.monotonic_ns())


def probe(executor, phase):
    before = executor.size("business.txt")
    result = executor.operation("append", "business.txt", phase + "|")
    after = executor.size("business.txt")
    result.update(phase=phase, before=before, after=after)
    assert (after - before == result["bytes"]) if result["ok"] else (
        after == before and result["errno"] in (errno.EACCES, errno.EPERM))
    return result


def trial(scenario, cooldown_ms):
    signer = BSigner()
    verifier = EvidenceVerifier("a", signer.get_public_key_bytes(), signer.get_h0())
    governor = Governance("a", Strategy.STAGED, int(cooldown_ms * 1e6))
    operations, applications = [], []
    with LinuxDACExecutor() as executor:
        operations.append(probe(executor, "positive-control"))
        assert operations[-1]["ok"]
        first = signed_case(signer, verifier, governor, "A")
        applications.append(governor.apply_current(executor))
        second = signed_case(signer, verifier, governor, "B")
        applications.append(governor.apply_current(executor))
        assert first != second and len(governor.open_cases) == 2

        governor.resolve(first, "innocent", time.monotonic_ns())
        operations.append(probe(executor, "first-innocent-second-pending"))
        assert not operations[-1]["ok"] and governor.state == State.PENDING

        if scenario == "overlap":
            governor.resolve(second, "innocent", time.monotonic_ns())
            time.sleep(cooldown_ms / 1000)
            governor.tick(time.monotonic_ns(), safe=True)
            assert governor.state == State.ACTIVE
            queued_restore = governor.revision
            # The restore command is prepared before a new case. A barrier
            # makes its delivery occur after the new restriction is applied.
            release = threading.Event()
            stale_result = []
            def delayed_restore():
                release.wait()
                stale_result.append(governor.apply_current(executor, queued_restore))
            thread = threading.Thread(target=delayed_restore)
            thread.start()
            third = signed_case(signer, verifier, governor, "C")
            applications.append(governor.apply_current(executor))
            release.set()
            thread.join(timeout=2)
            assert not thread.is_alive() and stale_result == [None]
            operations.append(probe(executor, "stale-restore-after-new-case"))
            assert not operations[-1]["ok"] and governor.state == State.PENDING
            governor.resolve(third, "innocent", time.monotonic_ns())
            verdict_ns = time.monotonic_ns()
            applications.append(governor.apply_current(executor))
            time.sleep(cooldown_ms / 1000)
            governor.tick(time.monotonic_ns(), safe=True)
            applications.append(governor.apply_current(executor))
            operations.append(probe(executor, "all-cases-resolved"))
            assert operations[-1]["ok"] and governor.state == State.ACTIVE
            recovery_ms = (operations[-1]["end_ns"] - verdict_ns) / 1e6
        else:
            governor.resolve(second, "innocent", time.monotonic_ns())
            time.sleep(cooldown_ms / 1000)
            governor.tick(time.monotonic_ns(), safe=True)
            assert governor.state == State.ACTIVE
            queued_restore = governor.revision
            third = signed_case(signer, verifier, governor, "C")
            fourth = signed_case(signer, verifier, governor, "D")
            applications.append(governor.apply_current(executor))
            governor.resolve(third, "guilty", time.monotonic_ns())
            applications.append(governor.apply_current(executor))
            governor.resolve(fourth, "innocent", time.monotonic_ns())
            stale = governor.apply_current(executor, queued_restore)
            assert stale is None
            time.sleep(cooldown_ms / 1000)
            governor.tick(time.monotonic_ns(), safe=True)
            operations.append(probe(executor, "terminal-after-stale-restore"))
            assert not operations[-1]["ok"] and governor.state == State.REVOKED
            recovery_ms = None
    return {"scenario": scenario, "cooldown_ms": cooldown_ms,
            "operations": operations, "applications": applications,
            "transitions": governor.transitions, "recovery_ms": recovery_ms,
            "rejected_stale_command": True,
            "final_state": governor.state.value}


def unguarded_negative_control(cooldown_ms):
    """Same case capabilities, but deliberately replay one old direct command."""
    signer = BSigner()
    verifier = EvidenceVerifier("a", signer.get_public_key_bytes(), signer.get_h0())
    governor = Governance("a", Strategy.STAGED, int(cooldown_ms * 1e6))
    with LinuxDACExecutor() as executor:
        first = signed_case(signer, verifier, governor, "A")
        governor.apply_current(executor)
        governor.resolve(first, "innocent", time.monotonic_ns())
        time.sleep(cooldown_ms / 1000)
        governor.tick(time.monotonic_ns(), safe=True)
        assert governor.state == State.ACTIVE
        old_revision, old_mode = governor.revision, governor.permissions
        signed_case(signer, verifier, governor, "B")
        governor.apply_current(executor)
        assert governor.state == State.PENDING
        executor.apply(old_mode)  # intentionally missing revision check
        violation = probe(executor, "unguarded-stale-restore")
        assert violation["ok"] and violation["after"] > violation["before"]
        governor.apply_current(executor)
        assert governor.apply_current(executor, old_revision) is None
        protected = probe(executor, "guarded-stale-restore")
        assert not protected["ok"] and protected["before"] == protected["after"]
    return {"cooldown_ms": cooldown_ms, "unguarded": violation, "guarded": protected}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    tasks = [(scenario, cooldown, repeat)
             for repeat in range(args.repeats)
             for scenario in ("overlap", "terminal")
             for cooldown in (0, 30)]
    random.Random(20261028).shuffle(tasks)
    args.output.mkdir(parents=True, exist_ok=False)
    source = [Path(__file__), Path("core/governance.py"), Path("core/linux_dac.py")]
    metadata = {"repeats_per_cell": args.repeats, "clock": "Linux monotonic_ns",
                "executor": "Linux DAC, root controller, uid 65534 worker, fresh opens",
                "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source}}
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2))
    rows = []
    with (args.output / "trials.jsonl").open("w") as out:
        for scenario, cooldown, repeat in tasks:
            row = trial(scenario, cooldown)
            row["repeat"] = repeat
            out.write(json.dumps(row) + "\n")
            out.flush()
            rows.append(row)
    summary = []
    for scenario in ("overlap", "terminal"):
        for cooldown in (0, 30):
            group = [r for r in rows if r["scenario"] == scenario and r["cooldown_ms"] == cooldown]
            summary.append({"scenario": scenario, "cooldown_ms": cooldown,
                            "n": len(group), "stale_rejected": sum(r["rejected_stale_command"] for r in group),
                            "forbidden_write_successes": sum(o["ok"] for r in group for o in r["operations"]
                                                             if o["phase"] in ("first-innocent-second-pending",
                                                                               "stale-restore-after-new-case",
                                                                               "terminal-after-stale-restore")),
                            "recovery_p50_ms": statistics.median(r["recovery_ms"] for r in group)
                                                if scenario == "overlap" else None,
                            "apply_p50_ms": statistics.median((a["end_ns"] - a["start_ns"]) / 1e6
                                                               for r in group for a in r["applications"] if a)})
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    # Isolate the additional revision check/lock against the same actual
    # executor call. The order is randomized within each pair.
    overhead = []
    governor = Governance("overhead", Strategy.STAGED)
    order_rng = random.Random(20261029)
    with LinuxDACExecutor() as executor:
        for _ in range(200):
            pair = {}
            order = ["direct", "guarded"]
            order_rng.shuffle(order)
            for variant in order:
                started = time.monotonic_ns()
                if variant == "direct":
                    executor.apply(governor.permissions)
                else:
                    assert governor.apply_current(executor, governor.revision) is not None
                pair[variant] = (time.monotonic_ns() - started) / 1e6
            overhead.append(pair)
    overhead_summary = {"pairs": len(overhead),
                        "direct_p50_ms": statistics.median(x["direct"] for x in overhead),
                        "guarded_p50_ms": statistics.median(x["guarded"] for x in overhead),
                        "paired_delta_p50_ms": statistics.median(x["guarded"] - x["direct"] for x in overhead)}
    (args.output / "overhead.json").write_text(json.dumps({"summary": overhead_summary,
                                                              "pairs": overhead}, indent=2))
    controls = []
    control_tasks = [c for _ in range(args.repeats) for c in (0, 30)]
    random.Random(20261030).shuffle(control_tasks)
    for cooldown in control_tasks:
        controls.append(unguarded_negative_control(cooldown))
    control_summary = {"trials": len(controls),
                       "unguarded_forbidden_writes": sum(x["unguarded"]["ok"] for x in controls),
                       "guarded_forbidden_writes": sum(x["guarded"]["ok"] for x in controls)}
    (args.output / "negative_control.json").write_text(json.dumps({"summary": control_summary,
                                                                     "trials": controls}, indent=2))
    print(json.dumps(summary, indent=2))
    print(json.dumps(overhead_summary, indent=2))
    print(json.dumps(control_summary, indent=2))


if __name__ == "__main__":
    main()
