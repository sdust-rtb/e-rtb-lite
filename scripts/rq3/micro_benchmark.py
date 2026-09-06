"""
RQ3: 组件级微基准测试

对应 §7.4.1：HMAC、Ed25519签名/验证、bsigner完整流程、风险评估延迟
运行环境：本地（环境1）
"""

import os
import sys
import time
import hmac
import hashlib
import statistics
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.bsigner import BSigner, BehaviorEvent


def pct(data, p):
    s = sorted(data)
    return s[min(int(len(s) * p / 100), len(s) - 1)]


def mean(data):
    return sum(data) / len(data) if data else 0.0


def std(data):
    m = mean(data)
    return (sum((x - m) ** 2 for x in data) / len(data)) ** 0.5 if data else 0.0


def ci95(data):
    """95% confidence interval half-width"""
    import math
    n = len(data)
    if n < 2:
        return 0.0
    return 1.96 * std(data) / math.sqrt(n)


def bench_hmac(n=10000):
    key, msg = os.urandom(32), os.urandom(64)
    lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        hmac.new(key, msg, hashlib.sha256).digest()
        lat.append((time.perf_counter_ns() - t0) / 1000)
    return {"component": "HMAC-SHA256 verify", "n": n,
            "mean_us": round(mean(lat), 1), "std_us": round(std(lat), 1),
            "ci95_us": round(ci95(lat), 1),
            "p50_us": pct(lat, 50), "p95_us": pct(lat, 95), "p99_us": pct(lat, 99)}


def bench_ed25519_sign(n=10000):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    msg = os.urandom(64)
    lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        key.sign(msg)
        lat.append((time.perf_counter_ns() - t0) / 1000)
    return {"component": "Ed25519 sign", "n": n,
            "mean_us": round(mean(lat), 1), "std_us": round(std(lat), 1),
            "ci95_us": round(ci95(lat), 1),
            "p50_us": pct(lat, 50), "p95_us": pct(lat, 95), "p99_us": pct(lat, 99)}


def bench_ed25519_verify(n=10000):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    sig = key.sign(os.urandom(64))
    lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        try:
            pub.verify(sig, os.urandom(64))
        except Exception:
            pass
        lat.append((time.perf_counter_ns() - t0) / 1000)
    return {"component": "Ed25519 verify", "n": n,
            "mean_us": round(mean(lat), 1), "std_us": round(std(lat), 1),
            "ci95_us": round(ci95(lat), 1),
            "p50_us": pct(lat, 50), "p95_us": pct(lat, 95), "p99_us": pct(lat, 99)}


def bench_bsigner_full(n=10000):
    bs = BSigner()
    lat = []
    for i in range(n):
        e = BehaviorEvent("openat", f"/test/{i}", "bench")
        m = bs.generate_channel_mac(e, i)
        t0 = time.perf_counter_ns()
        bs.verify_and_sign(e, m, i)
        lat.append((time.perf_counter_ns() - t0) / 1000)
    return {"component": "bsigner full sign", "n": n,
            "mean_us": round(mean(lat), 1), "std_us": round(std(lat), 1),
            "ci95_us": round(ci95(lat), 1),
            "p50_us": pct(lat, 50), "p95_us": pct(lat, 95), "p99_us": pct(lat, 99)}


def bench_risk_eval(n=10000):
    from rq4.dynamics_sim import RiskEngine
    eng = RiskEngine()
    lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        eng.update([0.3, 0.2, 0.1])
        lat.append((time.perf_counter_ns() - t0) / 1000)
    return {"component": "OPA risk evaluation", "n": n,
            "mean_us": round(mean(lat), 1), "std_us": round(std(lat), 1),
            "ci95_us": round(ci95(lat), 1),
            "p50_us": pct(lat, 50), "p95_us": pct(lat, 95), "p99_us": pct(lat, 99)}


def run_all_benchmarks(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 70)
    print("RQ3: 组件级微基准测试")
    print("=" * 70)

    benches = [bench_hmac, bench_ed25519_sign, bench_ed25519_verify, bench_bsigner_full, bench_risk_eval]
    results = []
    for fn in benches:
        print(f"\n  测试 {fn.__name__}...")
        r = fn()
        results.append(r)
        print(f"    P50={r['p50_us']:.1f}μs  P95={r['p95_us']:.1f}μs  P99={r['p99_us']:.1f}μs  "
              f"mean={r['mean_us']:.1f}±{r['ci95_us']:.1f}μs")

    print(f"\n{'=' * 70}")
    print(f"{'组件':<25} {'P50(μs)':>10} {'P95(μs)':>10} {'P99(μs)':>10} {'mean±CI':>14}")
    print("-" * 74)
    for r in results:
        print(f"{r['component']:<25} {r['p50_us']:>10.1f} {r['p95_us']:>10.1f} {r['p99_us']:>10.1f} "
              f"{r['mean_us']:>6.1f}±{r['ci95_us']:<5.1f}")
    print(f"{'=' * 74}")

    p = os.path.join(output_dir, "rq3_benchmark_results.json")
    with open(p, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n结果已保存至: {p}")
    return results


if __name__ == "__main__":
    run_all_benchmarks()
