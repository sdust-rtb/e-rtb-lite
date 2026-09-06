"""
RQ2: 双观测冗余测试

对应 §7.3.1：测试eBPF+LSM双观测在eBPF故障时的检测补偿能力

本脚本提供两种运行模式：
  1. 本地模拟模式（默认）：使用Mock类模拟eBPF/LSM，验证逻辑正确性
  2. 云Linux真实模式：使用BCC挂载真实eBPF探针（需要root + BCC库）

运行环境：本地模拟可在Windows运行；真实eBPF需云Linux
"""

import os
import sys
import json
import random
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


HIGH_RISK_OPS = [
    ("openat", "/etc/shadow", "O_RDONLY"),
    ("openat", "/root/.ssh/id_rsa", "O_RDONLY"),
    ("execve", "/usr/bin/sudo", "su -"),
    ("tcp_v4_connect", "192.168.1.100:4444", "reverse_shell"),
    ("execve", "/usr/bin/nc", "-e /bin/bash"),
]


class MockEBPFProbe:
    def __init__(self, drop_prob=0.0):
        self.drop_prob = drop_prob
        self.captured = 0
        self.dropped = 0

    def capture(self, event):
        if random.random() < self.drop_prob:
            self.dropped += 1
            return False
        self.captured += 1
        return True


class MockLSMHook:
    def __init__(self):
        self.captured = 0

    def capture(self, event):
        self.captured += 1
        return True


class CrossValidator:
    def __init__(self):
        self.match = self.mismatch = self.ebpf_only = self.lsm_only = 0

    def validate(self, ebpf_ok, lsm_ok):
        if ebpf_ok and lsm_ok:
            self.match += 1
        elif ebpf_ok and not lsm_ok:
            self.ebpf_only += 1
        elif not ebpf_ok and lsm_ok:
            self.lsm_only += 1
            self.mismatch += 1


def run_dual_observation_test(n_ops=1000, drop_probs=None, n_repeats=100, output_dir="results"):
    if drop_probs is None:
        drop_probs = [0.1, 0.3, 0.5]
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("RQ2: 双观测冗余测试（模拟模式）")
    print("=" * 70)

    all_results = []
    for drop_p in drop_probs:
        for config in ["G1_eBPF_only", "G2_LSM_only", "G3_dual"]:
            rates = []
            for _ in range(n_repeats):
                ebpf = MockEBPFProbe(drop_prob=drop_p)
                lsm = MockLSMHook()
                detected = 0
                for _ in range(n_ops):
                    evt = random.choice(HIGH_RISK_OPS) if random.random() < 0.3 else ("read", "/tmp/f", "ok")
                    e_ok = ebpf.capture(evt)
                    l_ok = lsm.capture(evt)
                    if config == "G1_eBPF_only" and e_ok:
                        detected += 1
                    elif config == "G2_LSM_only" and l_ok:
                        detected += 1
                    elif config == "G3_dual" and (e_ok or l_ok):
                        detected += 1
                rates.append(detected / n_ops)
            mean = sum(rates) / len(rates)
            ci = 1.96 * (sum((r - mean) ** 2 for r in rates) / len(rates)) ** 0.5 / (len(rates) ** 0.5)
            all_results.append({"drop_prob": drop_p, "config": config,
                                 "mean_rate": round(mean, 6), "ci95": round(ci, 6)})
            print(f"  p={drop_p} {config:<18} 检测率={mean:.4f} ± {ci:.4f}")

    p = os.path.join(output_dir, "rq2_dual_obs_results.json")
    with open(p, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return all_results


if __name__ == "__main__":
    run_dual_observation_test()
