#!/usr/bin/env python3
"""
E-RTB-Lite Agent-Node -- N>=30 Cross-Node Multi-Round Experiment

Usage: D:\Anaconda\python.exe cross_node_agent.py --url http://<CLOUD_IP>:5000 --rounds 30
"""
import sys, os, json, time, random, argparse, urllib.request, statistics
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core.bsigner import BSigner, BehaviorEvent

NORMAL_ACTIONS = [
    ("openat", "/app/data/config.json", "O_RDONLY"),
    ("openat", "/tmp/cache/session.dat", "O_RDWR"),
    ("read", "/app/logs/app.log", "4096"),
    ("write", "/app/output/report.csv", "1024"),
    ("tcp_v4_connect", "10.0.0.5:443", "HTTPS"),
    ("tcp_v4_connect", "10.0.0.10:8080", "API"),
    ("execve", "/usr/bin/python3", "script.py"),
    ("openat", "/var/data/db.sqlite", "O_RDONLY"),
    ("tcp_sendmsg", "10.0.0.5:443", "heartbeat"),
]

def build_65step_sequence():
    steps = []
    for i in range(1, 31):
        s = random.choice(NORMAL_ACTIONS)
        steps.append({"step": i, "syscall_type": s[0], "target_resource": s[1], "parameters": s[2]})
    steps.append({"step": 31, "syscall_type": "openat", "target_resource": "/etc/shadow", "parameters": "O_RDONLY"})
    for i in range(32, 66):
        s = random.choice(NORMAL_ACTIONS)
        steps.append({"step": i, "syscall_type": s[0], "target_resource": s[1], "parameters": s[2]})
    return steps

def run_single_round(round_id, registry_url, seed):
    random.seed(seed)
    bsigner = BSigner(did=f"agent-{round_id:03d}", node_id="node-agent", container_id="ctr-001")

    steps = build_65step_sequence()
    t_violation = None
    t_block = None
    blocked_count = 0
    total_post = 0
    all_rtts = []
    is_blocked = False

    for s in steps:
        evt = BehaviorEvent(
            syscall_type=s["syscall_type"],
            target_resource=s["target_resource"],
            parameters=s["parameters"]
        )
        seq = bsigner.seq_exp
        mac = bsigner.generate_channel_mac(evt, seq)
        pkg = bsigner.verify_and_sign(evt, mac, seq)

        req_data = json.dumps({
            "step": s["step"],
            "events": [{"syscall_type": s["syscall_type"], "target_resource": s["target_resource"]}]
        }).encode()

        t_start = time.time()
        try:
            req = urllib.request.Request(registry_url, data=req_data, headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=10)
            resp_data = json.loads(resp.read())
            rtt_ms = (time.time() - t_start) * 1000
            all_rtts.append(rtt_ms)

            state = resp_data.get("state", "active")

            if s["step"] == 31:
                t_violation = time.time()

            if state in ("probation", "revoked") and not is_blocked:
                is_blocked = True
                t_block = time.time()

            if s["step"] > 31:
                total_post += 1
                if is_blocked:
                    blocked_count += 1
        except Exception as e:
            all_rtts.append(-1)

    valid_rtts = [l for l in all_rtts if l > 0]
    return {
        "round": round_id,
        "revocation_latency_ms": round((t_block - t_violation) * 1000, 1) if t_block and t_violation else None,
        "blocked_rate": round(blocked_count / total_post, 4) if total_post else 1.0,
        "avg_rtt_ms": round(statistics.mean(valid_rtts), 1) if valid_rtts else 0,
        "total_blocked": blocked_count,
        "total_post_violation": total_post,
    }

def main():
    parser = argparse.ArgumentParser(description="E-RTB-Lite N>=30 Cross-Node Experiment")
    parser.add_argument("--url", default="http://localhost:5000/submit", help="Registry-node URL")
    parser.add_argument("--rounds", type=int, default=30)
    args = parser.parse_args()

    print(f"E-RTB-Lite N>={args.rounds} Cross-Node Experiment")
    print(f"Registry: {args.url}")
    print(f"{'='*60}")

    results = []
    for i in range(1, args.rounds + 1):
        r = run_single_round(i, args.url, seed=42 + i)
        results.append(r)
        lat = r["revocation_latency_ms"]
        print(f"  [{i:2d}/{args.rounds}] revoke_lat={lat}ms  rtt={r['avg_rtt_ms']}ms  blk={r['blocked_rate']:.1%}")

    # Statistics
    lats = sorted([r["revocation_latency_ms"] for r in results if r["revocation_latency_ms"]])
    if not lats:
        print("ERROR: No valid latency data - check network connection")
        return

    print(f"\n{'='*60}")
    print(f"N={len(lats)} Cross-Node Statistical Results")
    print(f"{'='*60}")
    print(f"  Mean:    {statistics.mean(lats):.1f} ms")
    print(f"  Median:  {statistics.median(lats):.1f} ms")
    print(f"  Std:     {statistics.stdev(lats):.1f} ms")
    print(f"  P50:     {lats[int(len(lats)*0.50)]:.1f} ms")
    print(f"  P95:     {lats[int(len(lats)*0.95)]:.1f} ms")
    print(f"  P99:     {lats[int(len(lats)*0.99)]:.1f} ms")
    print(f"  Min/Max: {min(lats):.1f} / {max(lats):.1f} ms")

    blk = [r["blocked_rate"] for r in results]
    print(f"\n  Mean Block Rate: {statistics.mean(blk):.1%}")
    print(f"  Total Post-Violation Events: {sum(r['total_post_violation'] for r in results)}")
    print(f"  Total Blocked: {sum(r['total_blocked'] for r in results)}")

    os.makedirs("results", exist_ok=True)
    out_path = f"results/cross_node_N{args.rounds}_{int(time.time())}.json"
    with open(out_path, "w") as f:
        json.dump({"n_rounds": args.rounds, "registry": args.url, "results": results}, f, indent=2)
    print(f"\nResults saved: {out_path}")

if __name__ == "__main__":
    main()
