"""Read-only verification of saved actual-operation trials and their signatures."""
import argparse
import errno
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.bsigner import BehaviorEvent, EvidencePackage
from core.governance import EvidenceVerifier


def verify(directory):
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    raw = directory / "trials.jsonl"
    assert metadata["status"] == "complete", "incomplete experiment"
    assert hashlib.sha256(raw.read_bytes()).hexdigest() == metadata["raw_sha256"]
    for name, expected in metadata["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, "source changed: " + name
    trials, events, pending_writes, bad_pending = 0, 0, 0, 0
    for line in raw.open(encoding="utf-8"):
        trial = json.loads(line)
        verifier = EvidenceVerifier("trial-agent", bytes.fromhex(trial["public_key"]), bytes.fromhex(trial["anchor"]))
        previous = -1
        for row in trial["operations"]:
            p = row["evidence"]
            package = EvidencePackage(bytes.fromhex(p["h_curr"]), p["seq"], bytes.fromhex(p["sigma"]), p["timestamp"], p["version"])
            event = BehaviorEvent(**row["event"])
            verifier.accept(event, package)
            signed_result = json.loads(event.parameters)
            assert all(row[k] == v for k, v in signed_result.items()), "unsigned outcome replacement"
            assert event.syscall_type == row["op"] and event.target_resource == row["name"]
            assert previous <= row["start_ns"] <= row["end_ns"] <= row["sign_start_ns"] <= row["sign_end_ns"] <= row["verify_end_ns"]
            previous = row["verify_end_ns"]
            expected_allowed = row["state"] == "Active" or (row["state"] in ("Probation", "Pending-Arbitration") and row["op"] == "read")
            assert row["expected_allowed"] == expected_allowed
            if expected_allowed:
                assert row["ok"] and row["errno"] is None and row["success"] and not row["denied"]
                expected_delta = row["bytes"] if row["op"] == "append" else 0
                assert row["size_after"] - row["size_before"] == expected_delta
            else:
                assert not row["ok"] and row["errno"] in (errno.EACCES, errno.EPERM)
                assert row["denied"] and not row["success"] and row["bytes"] == 0
                assert row["size_after"] == row["size_before"]
            if row["state"] == "Pending-Arbitration" and row["op"] == "append":
                pending_writes += 1
                bad_pending += int(row["ok"])
            events += 1
        assert verifier.next_seq == trial["metrics"]["verified_events"]
        work = [r for r in trial["operations"] if r["phase"] == "workload"]
        for prefix, name in (("danger", "sink.txt"), ("business", "business.txt")):
            rows = [r for r in work if r["name"] == name]
            assert trial["metrics"][prefix + "_attempts"] == len(rows)
            assert trial["metrics"][prefix + "_successes"] == sum(r["success"] for r in rows)
            assert trial["metrics"][prefix + "_denied"] == sum(r["denied"] for r in rows)
        assert trial["metrics"]["danger_bytes"] == sum(r["bytes"] for r in work if r["name"] == "sink.txt" and r["ok"])
        times = trial["times_ns"]
        for metric, stamp in (("restriction_apply_ms", "restriction_apply_end_ns"),
                              ("first_denial_ms", "first_denial_observed_ns"), ("hard_apply_ms", "hard_apply_end_ns"),
                              ("recovery_from_trigger_ms", "first_restored_write_ns")):
            expected = (times[stamp] - times["trigger_start_ns"]) / 1e6 if stamp in times else None
            assert trial["metrics"][metric] == expected
        if trial["strategy"] == "staged" and "jury_end_ns" in times:
            assert not any(t["to"] == "Active" and t["at_ns"] < times["jury_end_ns"] for t in trial["transitions"])
        trials += 1
    assert trials == metadata["completed_trials"]
    assert bad_pending == 0
    return {"verified_trials": trials, "verified_signed_operations": events,
            "pending_write_attempts": pending_writes, "pending_write_successes": bad_pending,
            "source_hashes_match": True, "raw_hash_matches": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
