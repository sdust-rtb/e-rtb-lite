#!/usr/bin/env python3
"""
RQ2: 真实eBPF观测探针运行器

在云Linux上挂载真实的eBPF探针到 sys_enter_openat，
统计指定时长内的事件捕获量和高风险路径检测数。

⚠ 运行环境：阿里云 Ubuntu 22.04（需要root权限 + BCC库）

安装：
  sudo apt update
  sudo apt install -y bpfcc-tools python3-bpfcc

运行：
  sudo python3 ebpf_runner.py 300        # 观测300秒
  sudo python3 ebpf_runner.py 300 -o /tmp/ebpf_out.json  # 指定输出路径

输出：
  JSON文件包含总事件数、高风险检测数、采样事件列表
"""

import os
import sys
import json
import time
import signal
import argparse
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    print("错误：需要安装BCC库")
    print("  Ubuntu: sudo apt install bpfcc-tools python3-bpfcc")
    print("  或:     pip install bcc")
    sys.exit(1)


# ──────────────────────── BPF C 程序 ────────────────────────

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct event_t {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u64 timestamp_ns;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(event_count, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                             args->filename);

    // 更新计数器
    u32 key = 0;
    u64 *val = event_count.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 init_val = 1;
        event_count.update(&key, &init_val);
    }

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""


# ──────────────────────── 高风险路径 ────────────────────────

HIGH_RISK_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "/etc/crontab",
    "/proc/self/mem",
    "/proc/self/exe",
    "/etc/ld.so.preload",
]


def is_high_risk(filename: str) -> bool:
    return any(hr in filename for hr in HIGH_RISK_PATHS)


# ──────────────────────── 主函数 ────────────────────────

def run_ebpf(duration_s: int = 300, output_path: str = None, sample_limit: int = 5000):
    """
    运行eBPF探针，捕获指定时长的 sys_enter_openat 事件

    Args:
        duration_s: 观测时长（秒）
        output_path: 输出JSON路径（默认 results/ebpf_events.json）
        sample_limit: 保存的采样事件上限
    """
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "..", "results", "ebpf_events.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[eBPF] 编译并加载BPF程序...")
    b = BPF(text=BPF_PROGRAM)

    events_data = []
    high_risk_count = 0
    total_received = 0
    running = True

    def handle_event(cpu, data, size):
        nonlocal total_received, high_risk_count
        total_received += 1

        evt = b["events"].event(data)
        filename = evt.filename.decode("utf-8", errors="replace")
        comm = evt.comm.decode("utf-8", errors="replace")

        hr = is_high_risk(filename)
        if hr:
            high_risk_count += 1

        # 只保存 sample_limit 条以控制输出大小
        if len(events_data) < sample_limit:
            events_data.append({
                "timestamp_ns": evt.timestamp_ns,
                "pid": evt.pid,
                "uid": evt.uid,
                "comm": comm,
                "filename": filename,
                "is_high_risk": hr,
            })

    b["events"].open_perf_buffer(handle_event, page_cnt=64)

    def signal_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"[eBPF] 探针已挂载到 sys_enter_openat")
    print(f"[eBPF] 观测时长: {duration_s}s | 高风险路径: {HIGH_RISK_PATHS}")
    print(f"[eBPF] 按 Ctrl+C 提前终止\n")

    start_time = time.time()
    last_report = start_time

    try:
        while running and (time.time() - start_time) < duration_s:
            b.perf_buffer_poll(timeout=1000)

            # 每30秒报告一次进度
            now = time.time()
            if now - last_report >= 30:
                elapsed = now - start_time
                rate = total_received / elapsed if elapsed > 0 else 0
                print(f"  [{elapsed:.0f}s] 事件: {total_received}  "
                      f"高风险: {high_risk_count}  "
                      f"速率: {rate:.0f} evt/s")
                last_report = now

    except KeyboardInterrupt:
        print("\n[eBPF] 用户中断")

    elapsed = time.time() - start_time

    # 读取内核计数器
    kernel_count = 0
    for k, v in b["event_count"].items():
        kernel_count = v.value

    # 保存结果
    result = {
        "metadata": {
            "duration_s": round(elapsed, 1),
            "timestamp": datetime.now().isoformat(),
            "kernel": os.uname().release,
            "sample_limit": sample_limit,
        },
        "counters": {
            "total_events_received": total_received,
            "kernel_event_count": kernel_count,
            "high_risk_detected": high_risk_count,
            "events_per_second": round(total_received / elapsed, 1) if elapsed > 0 else 0,
            "high_risk_ratio": round(high_risk_count / total_received, 6) if total_received > 0 else 0,
        },
        "sample_events": events_data[:sample_limit],
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"[eBPF] 观测完成:")
    print(f"  时长: {elapsed:.1f}s")
    print(f"  总事件: {total_received} (内核计数: {kernel_count})")
    print(f"  高风险检测: {high_risk_count}")
    print(f"  事件速率: {total_received / elapsed:.1f} evt/s")
    print(f"  结果: {os.path.abspath(output_path)}")
    print(f"{'=' * 60}")

    return result


# ──────────────────────── 双观测冗余实验 ────────────────────────

def run_dual_obs_experiment(duration_s: int = 60, output_path: str = None):
    """
    双观测冗余实验：在真实eBPF基础上模拟LSM冗余

    通过以下方式量化双观测增益：
    1. 统计eBPF探针的实际捕获率
    2. 模拟eBPF概率性丢包（10%/30%/50%）
    3. 假设LSM独立覆盖（基于AppArmor安全钩子）
    4. 计算G1/G2/G3三种配置的检测率
    """
    import random

    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "..", "results", "rq2_real_dual_obs.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[双观测] 运行真实eBPF探针 {duration_s}s...")

    # 先运行eBPF收集基线事件
    baseline_path = output_path.replace(".json", "_baseline.json")
    baseline = run_ebpf(duration_s=duration_s, output_path=baseline_path, sample_limit=10000)

    total = baseline["counters"]["total_events_received"]
    if total == 0:
        print("[双观测] 未捕获到事件，无法进行冗余分析")
        return None

    # 从采样事件中提取高风险事件比例
    samples = baseline["sample_events"]
    hr_ratio = sum(1 for e in samples if e["is_high_risk"]) / len(samples) if samples else 0

    print(f"\n[双观测] 基线: {total} 事件, 高风险比例: {hr_ratio:.4f}")
    print(f"[双观测] 模拟丢包场景...")

    drop_probs = [0.1, 0.3, 0.5]
    results = []

    for dp in drop_probs:
        for config in ["G1_eBPF_only", "G2_LSM_only", "G3_dual"]:
            # 模拟多次
            detection_rates = []
            for _ in range(100):
                detected = 0
                for e in samples:
                    # eBPF通道：以 (1-dp) 概率捕获
                    ebpf_ok = random.random() > dp
                    # LSM通道：独立于eBPF，假设99%捕获率
                    lsm_ok = random.random() > 0.01

                    if config == "G1_eBPF_only":
                        if ebpf_ok:
                            detected += 1
                    elif config == "G2_LSM_only":
                        if lsm_ok:
                            detected += 1
                    elif config == "G3_dual":
                        if ebpf_ok or lsm_ok:
                            detected += 1

                detection_rates.append(detected / len(samples))

            mean = sum(detection_rates) / len(detection_rates)
            ci = 1.96 * (sum((r - mean) ** 2 for r in detection_rates) / len(detection_rates)) ** 0.5 / (len(detection_rates) ** 0.5)

            results.append({
                "drop_prob": dp, "config": config,
                "mean_rate": round(mean, 6), "ci95": round(ci, 6),
            })
            print(f"  p={dp} {config:<18} 检测率={mean:.4f} ± {ci:.4f}")

    output = {
        "baseline": baseline["counters"],
        "drop_test_results": results,
    }
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n结果已保存至: {os.path.abspath(output_path)}")

    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E-RTB-Lite eBPF观测探针")
    parser.add_argument("duration", type=int, nargs="?", default=300,
                        help="观测时长（秒），默认300")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="输出JSON路径")
    parser.add_argument("--dual-obs", action="store_true",
                        help="运行双观测冗余实验")
    parser.add_argument("--sample-limit", type=int, default=5000,
                        help="采样事件保存上限")
    args = parser.parse_args()

    if args.dual_obs:
        run_dual_obs_experiment(duration_s=args.duration, output_path=args.output)
    else:
        run_ebpf(duration_s=args.duration, output_path=args.output,
                 sample_limit=args.sample_limit)
