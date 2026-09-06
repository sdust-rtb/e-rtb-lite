import os
import sys
import hmac
import hashlib
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.bsigner import BSigner, BehaviorEvent


def check_invariant(events, evidence_log, h0, pk_bytes):
    """三项不变量验证：签名、哈希链递推、序列单调性"""
    sig_ok = sig_fail = 0
    for pkg in evidence_log:
        if BSigner.verify_evidence(pkg, pk_bytes):
            sig_ok += 1
        else:
            sig_fail += 1

    chain_ok, chain_fail_at = True, -1
    h = h0
    for i, (evt, pkg) in enumerate(zip(events, evidence_log)):
        h = hmac.new(h, evt.feature_bytes() + i.to_bytes(8, "big"), hashlib.sha256).digest()
        if h != pkg.h_curr:
            chain_ok, chain_fail_at = False, i
            break

    seq_ok, seq_fail_at = True, -1
    prev = -1
    for i, pkg in enumerate(evidence_log):
        if pkg.seq <= prev:
            seq_ok, seq_fail_at = False, i
            break
        prev = pkg.seq

    return {
        "total": len(evidence_log), "sig_pass": sig_ok, "sig_fail": sig_fail,
        "chain_ok": chain_ok, "chain_fail_at": chain_fail_at,
        "seq_monotone": seq_ok, "seq_fail_at": seq_fail_at,
    }


def run_invariant_check(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 70)
    print("RQ1: 不变量保持验证 + 安全边界分离验证")
    print("=" * 70)

    bs = BSigner()
    h0, pk = bs.get_h0(), bs.get_public_key_bytes()
    events, evidence = [], []

    print("\n[阶段1] 正常签名10,000条事件...")
    for i in range(10000):
        e = BehaviorEvent(["openat", "execve", "tcp_v4_connect"][i % 3], f"/test/{i}", "test")
        m = bs.generate_channel_mac(e, i)
        p = bs.verify_and_sign(e, m, i)
        events.append(e)
        evidence.append(p)
    cp1 = check_invariant(events, evidence, h0, pk)
    print(f"  签名: {cp1['sig_pass']}/{cp1['total']}  链: {cp1['chain_ok']}  序列: {cp1['seq_monotone']}")

    print("\n[阶段2] 模拟eBPF卸载（5,000条事件不进入签名通道）...")
    unobserved = []
    for _ in range(5000):
        unobserved.append(BehaviorEvent("openat", "/etc/shadow", "O_RDONLY"))
    print(f"  未观测事件: {len(unobserved)} 条  证据日志: {len(evidence)} 条（未变化）")

    print("\n[阶段3] 恢复观测，继续签名5,000条...")
    for i in range(5000):
        e = BehaviorEvent("read", f"/app/data/{i}", "normal")
        m = bs.generate_channel_mac(e, bs.seq_exp)
        p = bs.verify_and_sign(e, m, bs.seq_exp)
        events.append(e)
        evidence.append(p)

    final = check_invariant(events, evidence, h0, pk)
    print(f"\n{'=' * 70}")
    print(f"最终验证（{final['total']}条证据包）:")
    print(f"  签名: {final['sig_pass']}/{final['total']}  链: {final['chain_ok']}  序列: {final['seq_monotone']}")
    print(f"\n结论: 观测丧失 → {len(unobserved)}条事件缺失（DoS）")
    print(f"       已签名证据完整性 → 不受影响")
    print(f"{'=' * 70}")

    out = {"checkpoint_1": cp1, "final": final, "unobserved_count": len(unobserved)}
    p = os.path.join(output_dir, "rq1_invariant_results.json")
    with open(p, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return out


if __name__ == "__main__":
    run_invariant_check()
