"""
RQ3: 并发压力测试（ThreadPoolExecutor + 锁保护）

对应 §7.4.4：逐步增加并发智能体数量，测量吞吐量和P95/P99延迟
运行环境：本地（环境1）
"""

import os
import sys
import time
import json
import threading
import concurrent.futures
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.bsigner import BSigner, BehaviorEvent


_signer_lock = threading.Lock()


def pct(data, p):
    s = sorted(data)
    return s[min(int(len(s) * p / 100), len(s) - 1)]


def agent_worker(agent_id, n_events, bsigner):
    latencies = []
    for i in range(n_events):
        e = BehaviorEvent(
            ["openat", "execve", "tcp_v4_connect"][i % 3],
            f"/agent/{agent_id}/res/{i}", "normal",
        )
        t0 = time.perf_counter_ns()
        with _signer_lock:
            seq = bsigner.seq_exp
            mac = bsigner.generate_channel_mac(e, seq)
            try:
                bsigner.verify_and_sign(e, mac, seq)
            except ValueError:
                pass
        latencies.append((time.perf_counter_ns() - t0) / 1000)
    return latencies


def run_stress_test(n_agents_list=None, events_per_agent=500, output_dir="results"):
    if n_agents_list is None:
        n_agents_list = [1, 5, 10, 20, 50]
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("RQ3: 并发压力测试（真实线程池 + 锁保护）")
    print("=" * 70)

    results = []
    for na in n_agents_list:
        bs = BSigner()
        total = na * events_per_agent
        all_lat = []

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=na) as ex:
            futs = [ex.submit(agent_worker, i, events_per_agent, bs) for i in range(na)]
            for f in concurrent.futures.as_completed(futs):
                all_lat.extend(f.result())
        elapsed = time.perf_counter() - t0
        tput = total / elapsed

        r = {"n_agents": na, "total_events": total, "elapsed_s": round(elapsed, 3),
             "throughput_eps": round(tput, 1), "p50_us": round(pct(all_lat, 50), 1),
             "p95_us": round(pct(all_lat, 95), 1), "p99_us": round(pct(all_lat, 99), 1)}
        results.append(r)
        print(f"  agents={na:>3}  events={total:>5}  tput={tput:>10.1f} eps  "
              f"P50={r['p50_us']:>8.1f}μs  P95={r['p95_us']:>8.1f}μs  P99={r['p99_us']:>8.1f}μs")

    p = os.path.join(output_dir, "rq3_stress_results.json")
    with open(p, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return results


if __name__ == "__main__":
    run_stress_test()
