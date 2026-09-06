import os
import sys
import time
import json
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.bsigner import (
    BSigner, BehaviorEvent, EvidencePackage,
    MACVerificationError, SequenceMismatchError,
)

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, desc="", **kwargs):
        print(f"  {desc}...")
        return iterable


def run_attack_a1_mac_forgery(bsigner, n_attempts=100000):
    """A1: 敌手无channel_key，提交随机MAC → 校验A拦截"""
    successes = 0
    failure_by_mac = 0
    failure_by_seq = 0
    for _ in tqdm(range(n_attempts), desc="A1 MAC forgery"):
        fake_event = BehaviorEvent(
            syscall_type=random.choice(["openat", "execve", "tcp_v4_connect"]),
            target_resource=f"/fake/path/{random.randint(0, 9999)}",
            parameters="forged",
        )
        forged_mac = os.urandom(32)
        try:
            bsigner.verify_and_sign(fake_event, forged_mac, bsigner.seq_exp)
            successes += 1
        except MACVerificationError:
            failure_by_mac += 1
        except SequenceMismatchError:
            failure_by_seq += 1
        except ValueError:
            failure_by_mac += 1
    return {
        "attack_type": "A1_MAC_forgery",
        "description": "No channel_key, random MAC",
        "n_attempts": n_attempts, "successes": successes,
        "failure_by_mac": failure_by_mac, "failure_by_seq": failure_by_seq,
        "success_rate": successes / n_attempts,
    }


def run_attack_a2_replay(bsigner, n_legitimate=1000, n_attempts=100000):
    """A2: 敌手有channel_key，用合法MAC重放旧seq → 校验B拦截"""
    legitimate_events = []
    for i in range(n_legitimate):
        event = BehaviorEvent(
            syscall_type=random.choice(["openat", "read", "write"]),
            target_resource=f"/app/data/{i}", parameters="normal",
        )
        mac = bsigner.generate_channel_mac(event, i)
        bsigner.verify_and_sign(event, mac, i)
        legitimate_events.append(event)

    successes = 0
    failure_by_mac = 0
    failure_by_seq = 0
    for _ in tqdm(range(n_attempts), desc="A2 Replay"):
        old_idx = random.randint(0, n_legitimate - 1)
        old_event = legitimate_events[old_idx]
        valid_mac = bsigner.generate_channel_mac(old_event, old_idx)
        try:
            bsigner.verify_and_sign(old_event, valid_mac, old_idx)
            successes += 1
        except MACVerificationError:
            failure_by_mac += 1
        except SequenceMismatchError:
            failure_by_seq += 1
        except ValueError:
            failure_by_seq += 1
    return {
        "attack_type": "A2_replay_with_channel_key",
        "description": "Has channel_key, valid MAC but stale seq",
        "n_legitimate": n_legitimate, "n_attempts": n_attempts,
        "successes": successes, "failure_by_mac": failure_by_mac,
        "failure_by_seq": failure_by_seq, "success_rate": successes / n_attempts,
    }


def run_attack_a3_hash_chain_tamper(bsigner, n_attempts=100000):
    """A3: 截获证据包，篡改h_curr，用随机私钥伪造签名 → 签名验证拦截"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    event = BehaviorEvent(syscall_type="openat", target_resource="/etc/passwd", parameters="O_RDONLY")
    mac = bsigner.generate_channel_mac(event, 0)
    legit_pkg = bsigner.verify_and_sign(event, mac, 0)

    successes = 0
    failures = 0
    for _ in tqdm(range(n_attempts), desc="A3 Hash tamper"):
        fake_h = os.urandom(32)
        fake_key = Ed25519PrivateKey.generate()
        ts = int(time.time()).to_bytes(8, "big")
        fake_sigma = fake_key.sign(fake_h + legit_pkg.seq.to_bytes(8, "big") + ts)
        fake_pkg = EvidencePackage(h_curr=fake_h, seq=legit_pkg.seq, sigma=fake_sigma)
        if BSigner.verify_evidence(fake_pkg, bsigner.get_public_key_bytes()):
            successes += 1
        else:
            failures += 1
    return {
        "attack_type": "A3_hash_chain_tamper",
        "description": "Tamper h_curr + random key signature",
        "n_attempts": n_attempts, "successes": successes,
        "failures": failures, "success_rate": successes / n_attempts,
    }


def run_all_attacks(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 70)
    print("RQ1: 证据完整性不变量验证 - 攻击实验")
    print("=" * 70)

    results = []

    print()
    bs1 = BSigner()
    t0 = time.time()
    r1 = run_attack_a1_mac_forgery(bs1)
    r1["elapsed_s"] = round(time.time() - t0, 1)
    results.append(r1)
    print(f"  成功: {r1['successes']} / {r1['n_attempts']}  拦截: MAC={r1['failure_by_mac']}  SEQ={r1['failure_by_seq']}  耗时: {r1['elapsed_s']}s\n")

    bs2 = BSigner()
    t0 = time.time()
    r2 = run_attack_a2_replay(bs2)
    r2["elapsed_s"] = round(time.time() - t0, 1)
    results.append(r2)
    print(f"  成功: {r2['successes']} / {r2['n_attempts']}  拦截: MAC={r2['failure_by_mac']}  SEQ={r2['failure_by_seq']}  耗时: {r2['elapsed_s']}s\n")

    bs3 = BSigner()
    t0 = time.time()
    r3 = run_attack_a3_hash_chain_tamper(bs3)
    r3["elapsed_s"] = round(time.time() - t0, 1)
    results.append(r3)
    print(f"  成功: {r3['successes']} / {r3['n_attempts']}  耗时: {r3['elapsed_s']}s")

    total_att = sum(r["n_attempts"] for r in results)
    total_succ = sum(r["successes"] for r in results)
    ci = 1 - (0.01 / 2) ** (1 / total_att) if total_succ == 0 else None

    print(f"\n{'=' * 70}")
    print(f"{'攻击类型':<32} {'尝试':>10} {'成功':>8} {'成功率':>12}")
    print("-" * 70)
    for r in results:
        print(f"{r['attack_type']:<32} {r['n_attempts']:>10} {r['successes']:>8} {r['success_rate']:>12.8f}")
    print(f"{'合计':<32} {total_att:>10} {total_succ:>8}")
    if ci:
        print(f"\nClopper-Pearson 99% CI上界: {ci:.2e}")
    print(f"{'=' * 70}")

    out = {"attacks": results, "total_attempts": total_att, "total_successes": total_succ, "ci_upper": ci}
    p = os.path.join(output_dir, "rq1_attack_results.json")
    with open(p, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return out


if __name__ == "__main__":
    run_all_attacks()
