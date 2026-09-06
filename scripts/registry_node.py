#!/usr/bin/env python3
"""
E-RTB-Lite Registry-Node - N=30 Cloud Server

Usage: python3 registry_node.py --port 5000
"""
import json, time, argparse
from flask import Flask, request, jsonify

app = Flask(__name__)
RISK_WINDOW = []
WINDOW_SIZE = 30
THETA_WARN = 0.25  # soft revocation
THETA_REVOKE = 0.50  # hard revocation

PATTERNS = {
    "/etc/shadow": 0.55, "/root/.ssh": 0.50,
    "/etc/passwd": 0.30, "/proc/self/mem": 0.45,
    "sudo": 0.35, "evil.com": 0.50,
}

def calc_risk(events):
    if isinstance(events, dict):
        events = [events]
    score = 0.0
    for e in events:
        resource = e.get("target_resource", "")
        syscall = e.get("syscall_type", "")
        for pat, w in PATTERNS.items():
            if pat in resource or pat in syscall:
                score = max(score, w)
    return score

@app.route("/submit", methods=["POST"])
def submit_evidence():
    global RISK_WINDOW
    t_recv = time.time()
    pkg = request.json or {}

    risk = calc_risk(pkg.get("events", [pkg]))
    RISK_WINDOW.append({"score": risk, "ts": t_recv})
    if len(RISK_WINDOW) > WINDOW_SIZE:
        RISK_WINDOW.pop(0)
    risk_t = max(w["score"] for w in RISK_WINDOW) if RISK_WINDOW else 0.0

    state = "active"
    if risk_t >= THETA_WARN:
        state = "probation"
    if risk_t >= THETA_REVOKE:
        state = "revoked"

    t_resp = time.time()
    return jsonify({
        "status": "ok", "state": state, "risk_score": round(risk_t, 4),
        "server_latency_ms": round((t_resp - t_recv) * 1000, 2),
        "step": pkg.get("step", 0)
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": time.time()})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    print(f"E-RTB-Lite Registry-Node: {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
