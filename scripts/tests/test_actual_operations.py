import os
import sys
import pytest
from core.experiment import ExecutionMismatch, run_trial
from core.linux_dac import LinuxDACExecutor

pytestmark = pytest.mark.skipif(sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
                                reason="actual DAC integration requires Linux root")


def test_kernel_denies_writes_but_allows_read_then_denies_both():
    with LinuxDACExecutor() as backend:
        assert backend.operation("append", "sink.txt", "first")["ok"]
        backend.apply("read-only")
        assert backend.operation("read", "diagnostic.txt")["ok"]
        result = backend.operation("append", "sink.txt", "forbidden")
        assert not result["ok"] and result["errno"] == 13
        assert backend.size("sink.txt") == len("first")
        backend.apply("deny-all")
        assert not backend.operation("read", "diagnostic.txt")["ok"]
        backend.apply("read-write")
        assert backend.operation("append", "sink.txt", "restored")["ok"]


class BrokenExecutor(LinuxDACExecutor):
    def apply(self, permissions):
        import time
        return {"start_ns": time.monotonic_ns(), "end_ns": time.monotonic_ns(), "permissions": permissions}


def test_noop_enforcer_invalidates_trial():
    with pytest.raises(ExecutionMismatch):
        run_trial("staged", "attack", 50, 0, executor_factory=BrokenExecutor)


@pytest.mark.parametrize("strategy", ["immediate", "wait", "staged"])
def test_actual_three_strategy_trials(strategy):
    trial = run_trial(strategy, "attack", 70, 0)
    m = trial["metrics"]
    assert trial["final_state"] == "Revoked"
    assert m["danger_denied"] > 0
    if strategy == "wait": assert m["danger_successes"] > 0
    else: assert m["danger_successes"] == 0


def test_false_positive_recovers_real_writes_after_verdict_and_cooldown():
    trial = run_trial("staged", "false_positive", 70, 0, cooldown_ms=30)
    m = trial["metrics"]
    assert trial["final_state"] == "Active"
    assert m["business_denied"] > 0 and m["business_successes"] > 0
    assert m["read_successes"] == m["read_attempts"]
    assert m["recovery_after_verdict_ms"] >= 30


def test_saved_events_can_be_verified_independently():
    from core.bsigner import BehaviorEvent, EvidencePackage
    from core.governance import EvidenceVerifier
    trial = run_trial("staged", "attack", 50, 0)
    verifier = EvidenceVerifier("trial-agent", bytes.fromhex(trial["public_key"]), bytes.fromhex(trial["anchor"]))
    for row in trial["operations"]:
        data = row["evidence"]
        pkg = EvidencePackage(bytes.fromhex(data["h_curr"]), data["seq"], bytes.fromhex(data["sigma"]),
                              data["timestamp"], data["version"])
        verifier.accept(BehaviorEvent(**row["event"]), pkg)
    assert verifier.next_seq == len(trial["operations"])
