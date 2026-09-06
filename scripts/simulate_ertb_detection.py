#!/usr/bin/env python3
"""将 VulnGym BL-AGENT-CAPABILITY 条目映射为 E-RTB Lite 风险评分场景。"""
import json
from pathlib import Path

base = Path(__file__).parent / "data"
in_path  = base / "agent_capability_subset.json"
out_path = base / "ertb_detection_results.json"

with open(in_path, encoding="utf-8") as f:
    entries = json.load(f)

# E-RTB Lite 风险评估参数（论文 Section 4）
THETA_WARN   = 0.25
THETA_ARB    = 0.50
THETA_REVOKE = 0.90

results = []
for e in entries:
    trace_depth = len(e.get("trace", []))
    risk_score = min(1.0, 0.15 + trace_depth * 0.12)

    if risk_score >= THETA_REVOKE:
        decision = "HARD-REVOKE"
    elif risk_score >= THETA_ARB:
        decision = "ARBITRATE"
    elif risk_score >= THETA_WARN:
        decision = "SOFT-REVOKE"
    else:
        decision = "MONITOR"

    results.append({
        "entry_id":      e["entry_id"],
        "project":       e["project"],
        "report_id":     e["report_id"],
        "vuln_title":    e["vuln_title"][:80],
        "risk_score":    round(risk_score, 3),
        "decision":      decision,
        "trace_depth":   trace_depth,
        "verify":        e.get("verify", 0),
    })

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print(f"{'Entry ID':15s} {'Project':15s} {'Trace':>5s} {'Risk':>6s} {'Decision':12s}")
print("-" * 60)
for r in results:
    print(f"{r['entry_id']:15s} {r['project']:15s} {r['trace_depth']:>5d} {r['risk_score']:>6.3f} {r['decision']:12s}")

decisions = [r["decision"] for r in results]
print(f"\n汇总: SOFT-REVOKE={decisions.count('SOFT-REVOKE')}, "
      f"ARBITRATE={decisions.count('ARBITRATE')}, "
      f"HARD-REVOKE={decisions.count('HARD-REVOKE')}, "
      f"MONITOR={decisions.count('MONITOR')}")
print(f"总计: {len(results)} 个 Advisory")
