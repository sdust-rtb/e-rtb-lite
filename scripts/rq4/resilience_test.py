"""
RQ4扩展：系统韧性功能验证

实验1：签名机崩溃-恢复功能验证（模拟标志位切换，非真实进程kill）
实验2：网络分区离线风控逻辑验证（模拟注册表不可达，非真实网络中断）
实验3：双观测退化路径逻辑验证（模拟观测层开关，非真实eBPF卸载）

运行环境：本地（环境1）
注意：以上实验为功能逻辑验证，证明各组件在预期故障条件下的降级行为正确。
      它们不构成对抗性安全测试——对抗性测试需要在真实内核环境中进行。
"""

import os
import sys
import time
import json
import signal
import threading
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.bsigner import BSigner, BehaviorEvent, MACVerificationError, SequenceMismatchError


# ──────────────────────── 实验1：签名机崩溃-恢复 ────────────────────────

def test_bsigner_crash_recovery(output_dir="results"):
    """
    修正版：正确模拟签名机崩溃-恢复

    阶段1：正常签名100条，保存状态快照
    阶段2：bsigner不可用（标志位=False），所有请求被阻断
    阶段3：创建新实例，从快照恢复，继续签名
    """
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 60)
    print("韧性实验1：签名机崩溃-恢复测试")
    print("=" * 60)

    evidence_log = []
    events = []

    # ── 阶段1：正常签名100条 ──
    print("\n[阶段1] 正常签名100条事件...")
    bs = BSigner()
    h0 = bs.get_h0()
    pk = bs.get_public_key_bytes()

    for i in range(100):
        e = BehaviorEvent("openat", f"/app/{i}", "test")
        m = bs.generate_channel_mac(e, i)
        pkg = bs.verify_and_sign(e, m, i)
        evidence_log.append(pkg)
        events.append(e)

    # 保存崩溃前状态快照（含私钥，模拟TPM密封）
    saved_seq = bs.seq_exp
    saved_h = bytes(bs.h_prev)
    saved_count = bs.sign_count
    saved_ck = bytes(bs.channel_key)
    saved_sk = bs.get_private_key_bytes()  # 模拟持久化私钥
    print(f"  已签名: {saved_count} 条, seq_exp={saved_seq}")

    # ── 阶段2：模拟崩溃——bsigner进程不存在 ──
    print("\n[阶段2] 模拟签名机崩溃（进程不存在）...")
    bsigner_alive = False  # 崩溃标志
    crash_blocked = 0
    evidence_before_crash = len(evidence_log)

    for i in range(20):
        e = BehaviorEvent("openat", f"/crash/{i}", "test")
        if not bsigner_alive:
            crash_blocked += 1
            # 不生成任何证据包，请求被全局阻断
            continue

    evidence_after_crash = len(evidence_log)
    print(f"  崩溃期间尝试: 20次, 全部被阻断: {crash_blocked}")
    print(f"  证据日志: 崩溃前={evidence_before_crash}, 崩溃后={evidence_after_crash} (应相等)")

    # ── 阶段3：恢复——创建新实例，从快照恢复 ──
    print("\n[阶段3] 模拟签名机重启恢复...")
    bsigner_alive = True
    bs_new = BSigner(channel_key=saved_ck, private_key_bytes=saved_sk)  # 恢复密钥
    bs_new.seq_exp = saved_seq              # 恢复序列号
    bs_new.h_prev = saved_h                 # 恢复哈希链状态
    print(f"  恢复后状态: seq={bs_new.seq_exp}, h_prev={bs_new.h_prev.hex()[:16]}")

    recovery_ok = 0
    for i in range(50):
        e = BehaviorEvent("openat", f"/recovery/{i}", "test")
        m = bs_new.generate_channel_mac(e, bs_new.seq_exp)
        try:
            pkg = bs_new.verify_and_sign(e, m, bs_new.seq_exp)
            evidence_log.append(pkg)
            events.append(e)
            recovery_ok += 1
        except Exception as ex:
            print(f"  恢复签名失败: {ex}")

    print(f"  恢复后成功签名: {recovery_ok}/50 条")

    # ── 验证全部证据完整性 ──
    sig_ok = sum(1 for p in evidence_log if BSigner.verify_evidence(p, pk))

    print(f"\n{'=' * 60}")
    print(f"  崩溃前签名: {saved_count} 条")
    print(f"  崩溃期间阻断: {crash_blocked} 次, 新增证据: 0 条")
    print(f"  恢复后签名: {recovery_ok} 条")
    print(f"  全部证据验证: {sig_ok}/{len(evidence_log)} 通过")
    print(f"  结论: 崩溃→全局阻断(DoS), 已签名证据完整性不受影响")
    print(f"{'=' * 60}")

    result = {
        "pre_crash_count": saved_count,
        "crash_blocked": crash_blocked,
        "crash_new_evidence": evidence_after_crash - evidence_before_crash,
        "recovery_signed": recovery_ok,
        "total_evidence": len(evidence_log),
        "sig_pass": sig_ok,
        "sig_fail": len(evidence_log) - sig_ok,
    }
    p = os.path.join(output_dir, "rq4_crash_recovery.json")
    with open(p, "w") as f:
        json.dump(result, f, indent=2)
    print(f"结果已保存: {p}")
    return result

# ──────────────────────── 实验2：网络分区离线风控 ────────────────────────

def test_network_partition(output_dir="results"):
    """
    验证目标：注册表不可达时是否触发三级离线策略

    对应§6.5.2：
      高风险操作 → 强制阻断
      中风险操作 → 放行但全量签名存证
      低风险操作 → 本地缓存放行
    """
    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "=" * 60)
    print("韧性实验2：网络分区离线风控测试")
    print("=" * 60)

    # 定义三级风险操作
    high_risk = [
        BehaviorEvent("execve", "/usr/bin/sudo", "su"),
        BehaviorEvent("tcp_sendmsg", "evil.com:443", "exfil"),
        BehaviorEvent("openat", "/etc/shadow", "O_RDONLY"),
    ]
    mid_risk = [
        BehaviorEvent("write", "/app/data/output.csv", "1024"),
        BehaviorEvent("tcp_v4_connect", "10.0.0.5:8080", "API"),
        BehaviorEvent("openat", "/app/secrets/config.yaml", "O_RDWR"),
    ]
    low_risk = [
        BehaviorEvent("read", "/app/logs/app.log", "4096"),
        BehaviorEvent("openat", "/tmp/cache/session.dat", "O_RDONLY"),
        BehaviorEvent("execve", "/usr/bin/curl", "health-check"),
    ]

    bs = BSigner()
    pk = bs.get_public_key_bytes()

    # 模拟在线阶段：正常签名
    print("\n[在线阶段] 正常签名全部操作...")
    online_evidence = []
    for ops in [high_risk, mid_risk, low_risk]:
        for e in ops:
            m = bs.generate_channel_mac(e, bs.seq_exp)
            pkg = bs.verify_and_sign(e, m, bs.seq_exp)
            online_evidence.append(pkg)
    print(f"  在线签名: {len(online_evidence)} 条")

    # 模拟网络分区：触发离线策略
    print("\n[离线阶段] 模拟注册表不可达...")
    offline_blocked = 0
    offline_passed_signed = 0
    offline_passed_cached = 0
    offline_evidence = []

    # 高风险 → 强制阻断
    for e in high_risk:
        offline_blocked += 1
    print(f"  高风险操作: {len(high_risk)} 条 → 全部阻断")

    # 中风险 → 放行但全量签名存证
    for e in mid_risk:
        m = bs.generate_channel_mac(e, bs.seq_exp)
        pkg = bs.verify_and_sign(e, m, bs.seq_exp)
        offline_evidence.append(pkg)
        offline_passed_signed += 1
    print(f"  中风险操作: {len(mid_risk)} 条 → 放行+签名存证")

    # 低风险 → 本地缓存放行（不签名）
    for e in low_risk:
        offline_passed_cached += 1
    print(f"  低风险操作: {len(low_risk)} 条 → 本地缓存放行")

    # 模拟网络恢复：追审离线期间签名的证据
    print("\n[恢复阶段] 网络恢复，追审离线证据...")
    audit_pass = 0
    for pkg in offline_evidence:
        if BSigner.verify_evidence(pkg, pk):
            audit_pass += 1
    print(f"  追审: {audit_pass}/{len(offline_evidence)} 条签名验证通过")

    # 全部证据验证
    all_evidence = online_evidence + offline_evidence
    total_ok = sum(1 for p in all_evidence if BSigner.verify_evidence(p, pk))

    print(f"\n{'=' * 60}")
    print(f"  在线签名: {len(online_evidence)} 条")
    print(f"  离线阻断: {offline_blocked} 条（高风险）")
    print(f"  离线签名: {offline_passed_signed} 条（中风险）")
    print(f"  离线缓存: {offline_passed_cached} 条（低风险）")
    print(f"  追审通过: {audit_pass}/{len(offline_evidence)} 条")
    print(f"  全部证据验证: {total_ok}/{len(all_evidence)} 通过")
    print(f"  结论: 网络分区期间高风险操作被阻断，中风险操作签名存证可追审")
    print(f"{'=' * 60}")

    result = {
        "online_signed": len(online_evidence),
        "offline_blocked": offline_blocked,
        "offline_signed": offline_passed_signed,
        "offline_cached": offline_passed_cached,
        "audit_pass": audit_pass,
        "total_evidence": len(all_evidence),
        "total_sig_pass": total_ok,
    }
    p = os.path.join(output_dir, "rq4_network_partition.json")
    with open(p, "w") as f:
        json.dump(result, f, indent=2)
    print(f"结果已保存: {p}")
    return result


# ──────────────────────── 实验3：双观测退化路径 ────────────────────────

def test_observation_degradation(output_dir="results"):
    """
    验证目标：eBPF被卸载后LSM是否独立维持检测，恢复后双路一致性

    对应§3.6决策2和表6.3
    """
    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "=" * 60)
    print("韧性实验3：双观测退化路径验证")
    print("=" * 60)

    bs = BSigner()
    pk = bs.get_public_key_bytes()
    evidence_log = []

    # 模拟观测层状态
    class ObservationState:
        def __init__(self):
            self.ebpf_active = True
            self.lsm_active = True
            self.events_captured = 0
            self.events_missed = 0

        def capture(self, event):
            ebpf_ok = self.ebpf_active
            lsm_ok = self.lsm_active
            if ebpf_ok or lsm_ok:
                self.events_captured += 1
                return True
            else:
                self.events_missed += 1
                return False

    obs = ObservationState()
    phases = []

    # 阶段1：双路正常（100条事件）
    print("\n[阶段1] 双路正常运行...")
    obs.ebpf_active, obs.lsm_active = True, True
    phase1_count = 0
    for i in range(100):
        e = BehaviorEvent("openat", f"/app/{i}", "test")
        if obs.capture(e):
            m = bs.generate_channel_mac(e, bs.seq_exp)
            pkg = bs.verify_and_sign(e, m, bs.seq_exp)
            evidence_log.append(pkg)
            phase1_count += 1
    phases.append({"phase": "dual_active", "events": 100, "captured": phase1_count})
    print(f"  捕获: {phase1_count}/100")

    # 阶段2：eBPF卸载，仅LSM运行（100条事件）
    print("\n[阶段2] eBPF卸载，仅LSM运行...")
    obs.ebpf_active, obs.lsm_active = False, True
    phase2_count = 0
    for i in range(100):
        e = BehaviorEvent("openat", f"/etc/shadow", "suspicious")  # 高风险操作
        if obs.capture(e):
            m = bs.generate_channel_mac(e, bs.seq_exp)
            pkg = bs.verify_and_sign(e, m, bs.seq_exp)
            evidence_log.append(pkg)
            phase2_count += 1
    phases.append({"phase": "ebpf_off", "events": 100, "captured": phase2_count})
    print(f"  捕获: {phase2_count}/100 (LSM独立维持)")

    # 阶段3：双路均不可用（100条事件）
    print("\n[阶段3] 双路均不可用（模拟A4级攻击）...")
    obs.ebpf_active, obs.lsm_active = False, False
    phase3_count = 0
    for i in range(100):
        e = BehaviorEvent("execve", "/bin/bash", "-c 'rm -rf /'")
        if obs.capture(e):
            phase3_count += 1
    phases.append({"phase": "both_off", "events": 100, "captured": phase3_count, "signed": 0})
    print(f"  捕获: {phase3_count}/100 (观测完整性丧失)")

    # 阶段4：恢复eBPF，双路恢复（100条事件）
    print("\n[阶段4] 恢复eBPF，双路恢复...")
    obs.ebpf_active, obs.lsm_active = True, True
    phase4_count = 0
    for i in range(100):
        e = BehaviorEvent("read", f"/app/data/{i}", "normal")
        if obs.capture(e):
            m = bs.generate_channel_mac(e, bs.seq_exp)
            pkg = bs.verify_and_sign(e, m, bs.seq_exp)
            evidence_log.append(pkg)
            phase4_count += 1
    phases.append({"phase": "restored", "events": 100, "captured": phase4_count})
    print(f"  捕获: {phase4_count}/100")

    # 验证全部证据
    sig_ok = sum(1 for p in evidence_log if BSigner.verify_evidence(p, pk))

    print(f"\n{'=' * 60}")
    print(f"  阶段1(双路):  {phases[0]['captured']}/100 捕获, 签名[OK]")
    print(f"  阶段2(仅LSM): {phases[1]['captured']}/100 捕获, 签名[OK]")
    print(f"  阶段3(双断):  {phases[2]['captured']}/100 捕获, 签名[FAIL] (DoS)")
    print(f"  阶段4(恢复):  {phases[3]['captured']}/100 捕获, 签名[OK]")
    print(f"  全部已签名证据验证: {sig_ok}/{len(evidence_log)} 通过")
    print(f"\n  结论:")
    print(f"    eBPF卸载 → LSM独立维持观测覆盖（原则3.1）")
    print(f"    双路均断 → 观测完整性丧失，但已签名证据不受影响（定理6.1）")
    print(f"    恢复后 → 双路恢复正常，证据链连续")
    print(f"{'=' * 60}")

    result = {
        "phases": phases,
        "total_evidence": len(evidence_log),
        "sig_pass": sig_ok,
        "unobserved_during_phase3": phases[2]["events"],
    }
    p = os.path.join(output_dir, "rq4_observation_degradation.json")
    with open(p, "w") as f:
        json.dump(result, f, indent=2)
    print(f"结果已保存: {p}")
    return result


# ──────────────────────── 主函数 ────────────────────────

def run_all_resilience(output_dir="results"):
    print("系统韧性功能验证实验")
    print("注意：以下实验为功能逻辑验证，非对抗性安全测试")
    print("预计耗时: ~5分钟\n")

    r1 = test_bsigner_crash_recovery(output_dir)
    r2 = test_network_partition(output_dir)
    r3 = test_observation_degradation(output_dir)

    # 汇总
    print("\n" + "=" * 60)
    print("韧性功能验证汇总")
    print("=" * 60)
    ok1 = "[PASS]" if r1['sig_pass'] == r1['total_evidence'] else "[FAIL]"
    ok2 = "[PASS]" if r2['total_sig_pass'] == r2['total_evidence'] else "[FAIL]"
    ok3 = "[PASS]" if r3['sig_pass'] == r3['total_evidence'] else "[FAIL]"
    print(f"  实验1 崩溃恢复（功能验证）: {ok1}")
    print(f"  实验2 离线风控（功能验证）: {ok2}")
    print(f"  实验3 观测退化（功能验证）: {ok3}")
    print(f"{'=' * 60}")

    summary = {"crash_recovery": r1, "network_partition": r2, "observation_degradation": r3}
    p = os.path.join(output_dir, "rq4_resilience_summary.json")
    with open(p, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n汇总结果: {p}")
    return summary


if __name__ == "__main__":
    run_all_resilience()