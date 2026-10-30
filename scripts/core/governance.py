"""Shared evidence validation and governance state machine.

The verifier is provisioned with a trusted per-agent key and chain anchor.
It authenticates raw events before any policy decision, and commits sequence
state only after all checks pass. Durable storage and multi-node consensus are
outside this single-process experiment.
"""
import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from enum import Enum

from core.bsigner import BSigner, BehaviorEvent


class EvidenceRejected(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedEvent:
    agent_id: str
    sequence: int
    chain_hash: str
    syscall_type: str
    target_resource: str
    parameters: str
    timestamp_ns: int


class EvidenceVerifier:
    def __init__(self, agent_id, public_key, anchor):
        self.agent_id = agent_id
        self.public_key = bytes(public_key)
        self.head = bytes(anchor)
        self.next_seq = 0
        self._lock = threading.Lock()

    def accept(self, event, package):
        # Snapshot both objects to avoid mutation between validation and use.
        from core.bsigner import EvidencePackage
        try:
            event = BehaviorEvent(event.syscall_type, event.target_resource,
                                  event.parameters, event.timestamp_ns)
            package = EvidencePackage(bytes(package.h_curr), package.seq,
                                      bytes(package.sigma), package.timestamp, package.version)
            encoded = event.feature_bytes()
        except Exception as exc:
            raise EvidenceRejected("malformed evidence") from exc
        with self._lock:
            if package.seq != self.next_seq:
                raise EvidenceRejected("replay, gap, or out-of-order evidence")
            if not BSigner.verify_evidence(package, self.public_key):
                raise EvidenceRejected("invalid signature")
            expected = hmac.new(self.head, encoded + package.seq.to_bytes(8, "big"),
                                hashlib.sha256).digest()
            if not hmac.compare_digest(expected, package.h_curr):
                raise EvidenceRejected("event does not match authenticated chain")
            self.head = package.h_curr
            self.next_seq += 1
            return VerifiedEvent(self.agent_id, package.seq, package.h_curr.hex(),
                                 event.syscall_type, event.target_resource,
                                 event.parameters, event.timestamp_ns)


class State(str, Enum):
    ACTIVE = "Active"
    PROBATION = "Probation"
    PENDING = "Pending-Arbitration"
    REVOKED = "Revoked"


class Strategy(str, Enum):
    IMMEDIATE = "immediate"
    WAIT = "wait"
    STAGED = "staged"


class Governance:
    """Pending ALWAYS denies writes. The wait baseline stays Active with an
    outstanding case; it deliberately does not enter the restrictive Pending state.
    A confirmed innocent verdict starts a consecutive-safe cooldown in Probation.
    An absent/invalid verdict never clears a pending case.
    """
    def __init__(self, agent_id, strategy, cooldown_ns=0, policy_version="file-policy-v2"):
        self.agent_id = agent_id
        self.strategy = Strategy(strategy)
        self.cooldown_ns = cooldown_ns
        self.policy_version = policy_version
        self.state = State.ACTIVE
        self.case_open = False
        self.safe_since = None
        self.case_id = None
        self.version = 0
        self.transitions = []

    def _move(self, state, now_ns, cause):
        if self.state == State.REVOKED or state == self.state:
            return
        previous = self.state
        self.state = state
        self.version += 1
        self.transitions.append({"at_ns": now_ns, "from": previous.value,
                                 "to": state.value, "version": self.version,
                                 "policy_version": self.policy_version, "cause": cause})

    def open_case(self, evidence, now_ns):
        if not isinstance(evidence, VerifiedEvent) or evidence.agent_id != self.agent_id:
            raise EvidenceRejected("decision requires this agent's verified evidence")
        if self.state == State.REVOKED or self.case_open:
            return self.case_id
        self.case_id = evidence.chain_hash
        self.case_open = True
        self.safe_since = None
        if self.strategy == Strategy.IMMEDIATE:
            self._move(State.REVOKED, now_ns, self.case_id)
        elif self.strategy == Strategy.STAGED:
            self._move(State.PROBATION, now_ns, self.case_id)
            self._move(State.PENDING, now_ns, self.case_id)
        return self.case_id

    def resolve(self, case_id, verdict, now_ns):
        if not self.case_open or case_id != self.case_id:
            raise ValueError("stale or unknown verdict")
        if verdict not in ("guilty", "innocent"):
            return  # abstention / error: keep pending and restricted
        self.case_open = False
        if verdict == "guilty":
            self._move(State.REVOKED, now_ns, case_id)
        elif self.state == State.PENDING:
            self.safe_since = now_ns
            self._move(State.PROBATION, now_ns, case_id)
            self.tick(now_ns, safe=True)

    def tick(self, now_ns, safe):
        if self.state != State.PROBATION or self.case_open:
            return
        if not safe:
            self.safe_since = None
        elif self.safe_since is None:
            self.safe_since = now_ns
        if safe and now_ns - self.safe_since >= self.cooldown_ns:
            self._move(State.ACTIVE, now_ns, "consecutive-safe-cooldown")

    @property
    def permissions(self):
        return {State.ACTIVE: "read-write", State.PROBATION: "read-only",
                State.PENDING: "read-only", State.REVOKED: "deny-all"}[self.state]


def python_risk_rule(event):
    """Explicit Python rule, not OPA. Only authenticated successful reads count."""
    if not isinstance(event, VerifiedEvent):
        raise EvidenceRejected("unverified input to policy")
    params = json.loads(event.parameters)
    return (event.syscall_type == "read" and event.target_resource == "sensitive.txt"
            and params.get("ok") is True)
