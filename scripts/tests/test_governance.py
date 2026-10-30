from dataclasses import replace
import pytest
from core.bsigner import BSigner, BehaviorEvent, MACVerificationError
from core.governance import (EvidenceRejected, EvidenceVerifier, Governance,
                             State, Strategy, python_risk_rule)


def signed_event():
    signer = BSigner()
    verifier = EvidenceVerifier("a", signer.get_public_key_bytes(), signer.get_h0())
    event = BehaviorEvent("read", "sensitive.txt", '{"ok":true}')
    package = signer.verify_and_sign(event, signer.generate_channel_mac(event, 0), 0)
    return event, package, verifier


def test_delimiter_collision_is_rejected():
    signer = BSigner()
    first = BehaviorEvent("openat", "/tmp/a|b", "c", 1)
    other = BehaviorEvent("openat", "/tmp/a", "b|c", 1)
    with pytest.raises(MACVerificationError):
        signer.verify_and_sign(other, signer.generate_channel_mac(first, 0), 0)


@pytest.mark.parametrize("kind", ["resource", "parameters", "observation_time", "signature", "signing_time", "version", "gap"])
def test_tampered_input_never_advances_verifier(kind):
    event, package, verifier = signed_event()
    bad_event, bad_package = event, package
    if kind == "resource": bad_event = replace(event, target_resource="other")
    elif kind == "parameters": bad_event = replace(event, parameters='{"ok":false}')
    elif kind == "observation_time": bad_event = replace(event, timestamp_ns=event.timestamp_ns + 1)
    elif kind == "signature": bad_package = replace(package, sigma=b"x" * 64)
    elif kind == "signing_time": bad_package = replace(package, timestamp=package.timestamp + 1)
    elif kind == "version": bad_package = replace(package, version=1)
    elif kind == "gap": bad_package = replace(package, seq=1)
    with pytest.raises(EvidenceRejected): verifier.accept(bad_event, bad_package)
    assert verifier.next_seq == 0
    assert python_risk_rule(verifier.accept(event, package))
    with pytest.raises(EvidenceRejected): verifier.accept(event, package)


def test_wrong_anchor_key_and_unverified_policy_input():
    event, package, verifier = signed_event()
    wrong = EvidenceVerifier("a", verifier.public_key, b"x" * 32)
    with pytest.raises(EvidenceRejected): wrong.accept(event, package)
    wrong = EvidenceVerifier("a", BSigner().get_public_key_bytes(), verifier.head)
    with pytest.raises(EvidenceRejected): wrong.accept(event, package)
    with pytest.raises(EvidenceRejected): python_risk_rule(event)


def opened(strategy=Strategy.STAGED, cooldown=10):
    event, package, verifier = signed_event()
    gov = Governance("a", strategy, cooldown)
    gov.open_case(verifier.accept(event, package), 0)
    return gov


def test_pending_does_not_restore_when_delay_exceeds_cooldown():
    gov = opened()
    for now in range(1, 100):
        gov.tick(now, safe=True)
        assert gov.state == State.PENDING and gov.permissions == "read-only"
    gov.resolve(gov.case_id, "error", 100)
    gov.tick(200, safe=True)
    assert gov.state == State.PENDING


def test_innocent_requires_consecutive_safe_cooldown():
    gov = opened()
    gov.resolve(gov.case_id, "innocent", 100)
    assert gov.state == State.PROBATION
    gov.tick(109, safe=True)
    assert gov.state == State.PROBATION
    gov.tick(110, safe=False)
    gov.tick(111, safe=True)
    gov.tick(120, safe=True)
    assert gov.state == State.PROBATION
    gov.tick(121, safe=True)
    assert gov.state == State.ACTIVE


@pytest.mark.parametrize("strategy", list(Strategy))
def test_guilty_is_permanent(strategy):
    gov = opened(strategy)
    gov.resolve(gov.case_id, "guilty", 100)
    gov.tick(1000000, safe=True)
    assert gov.state == State.REVOKED and gov.permissions == "deny-all"
    with pytest.raises(ValueError): gov.resolve(gov.case_id, "innocent", 1000001)


def test_wait_is_explicit_unrestricted_baseline_not_pending():
    gov = opened(Strategy.WAIT)
    assert gov.case_open and gov.state == State.ACTIVE
    assert gov.permissions == "read-write"
    with pytest.raises(ValueError): gov.resolve("stale", "innocent", 100)


def test_original_slow_arbitration_regression():
    from rq4.state_ablation import simulate, scenario_slow_arb
    rec, metrics = simulate("S3", scenario_slow_arb, "slow_arb")
    assert all(rec["status"][i] == "J" for i in range(20, 40))
    assert rec["status"][40] == "R"
    assert metrics["false_restore_count"] == 0
    assert metrics["privileged_steps"] == 0


def test_new_violation_resets_simulated_safe_steps():
    from rq4.state_ablation import simulate, scenario_fluctuating
    rec, _ = simulate("S3", scenario_fluctuating, "fluctuating")
    assert "A" not in rec["status"]  # violations recur before ten safe steps
