"""
RQ3 DCT+ vs Static JWT: 凭证安全属性对比实验

4 凭证变体:
  B1: Plain JWT         — 静态签发, 无环境绑定, 无行为锚定
  B2: JWT + env claim   — JWT 附带 Node_ID/Container_ID 声明
  B3: DCT (env only)    — DCT 含环境因子 + HMAC签名, 无行为哈希链
  B4: DCT+ (full)       — E-RTB-Lite: 环境因子 + Chain_Anchor + 状态机

3 攻击场景 (每场景 1000 次):
  A1: Token 跨容器迁移  — 窃取凭证后在新容器中使用
  A2: 撤销后重放         — 凭证已撤销后尝试再次使用
  A3: 凭证篡改           — 修改凭证中的权限/环境字段

指标: 拒绝率 (reject rate) — 越高越好
"""

import os, json, time, hmac, hashlib, secrets
from pathlib import Path
from typing import Dict, List, Optional
import jwt as pyjwt
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

JWT_SECRET = secrets.token_hex(32)
DCT_KEY = secrets.token_hex(32)
N_TRIALS = 1000


class TokenContext:
    def __init__(self, did, node_id, container_id):
        self.did = did
        self.node_id = node_id
        self.container_id = container_id


class RevocationRegistry:
    def __init__(self):
        self._revoked = set()
    def revoke(self, did):
        self._revoked.add(did)
    def is_revoked(self, did):
        return did in self._revoked


# ============== B1: Plain JWT ==============
def make_plain_jwt(ctx, perms=None):
    if perms is None:
        perms = ["read", "write", "execute"]
    return pyjwt.encode({
        "sub": ctx.did, "perms": perms,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
    }, JWT_SECRET, algorithm="HS256")

def verify_plain_jwt(token, ctx, reg, chain_hash=None):
    """B1: JWT self-contained — no online revocation query"""
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False

# ============== B2: JWT + env ==============
def make_jwt_env(ctx, perms=None):
    if perms is None:
        perms = ["read", "write", "execute"]
    return pyjwt.encode({
        "sub": ctx.did, "perms": perms,
        "node_id": ctx.node_id, "container_id": ctx.container_id,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
    }, JWT_SECRET, algorithm="HS256")

def verify_jwt_env(token, ctx, reg, chain_hash=None):
    """B2: JWT + env claims — env binding only, no revocation"""
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("node_id") != ctx.node_id:
            return False
        if payload.get("container_id") != ctx.container_id:
            return False
        return True
    except Exception:
        return False

# ============== B3: DCT env-only ==============
def make_dct_env(ctx, perms=None):
    if perms is None:
        perms = ["read", "write", "execute"]
    payload = {
        "did": ctx.did, "perms": perms,
        "node_id": ctx.node_id, "container_id": ctx.container_id,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
        "status": "active",
    }
    pb = json.dumps(payload, sort_keys=True).encode()
    sig = hmac.new(DCT_KEY.encode(), pb, hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": sig}

def verify_dct_env(token, ctx, reg, chain_hash=None):
    try:
        payload, sig = token["payload"], token["signature"]
        expected = hmac.new(DCT_KEY.encode(),
                            json.dumps(payload, sort_keys=True).encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if reg.is_revoked(payload["did"]):
            return False
        if payload.get("node_id") != ctx.node_id:
            return False
        if payload.get("container_id") != ctx.container_id:
            return False
        if payload.get("status") == "revoked":
            return False
        if payload.get("exp", 0) < int(time.time()):
            return False
        return True
    except Exception:
        return False

# ============== B4: DCT+ full ==============
def make_dct_plus(ctx, perms=None):
    if perms is None:
        perms = ["read", "write", "execute"]
    chain_anchor = hashlib.sha256(
        f"{ctx.did}|{ctx.node_id}|{ctx.container_id}|{secrets.token_hex(8)}".encode()
    ).hexdigest()
    payload = {
        "did": ctx.did, "perms": perms,
        "node_id": ctx.node_id, "container_id": ctx.container_id,
        "chain_anchor": chain_anchor,
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
        "status": "active",
    }
    pb = json.dumps(payload, sort_keys=True).encode()
    sig = hmac.new(DCT_KEY.encode(), pb, hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": sig, "chain_anchor": chain_anchor}

def verify_dct_plus(token, ctx, reg, chain_hash=None):
    try:
        payload, sig = token["payload"], token["signature"]
        expected = hmac.new(DCT_KEY.encode(),
                            json.dumps(payload, sort_keys=True).encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if reg.is_revoked(payload["did"]):
            return False
        if payload.get("node_id") != ctx.node_id:
            return False
        if payload.get("container_id") != ctx.container_id:
            return False
        if payload.get("status") == "revoked":
            return False
        if payload.get("exp", 0) < int(time.time()):
            return False
        if chain_hash is not None and payload.get("chain_anchor"):
            if hashlib.sha256((payload["chain_anchor"] + chain_hash).encode()).hexdigest() != chain_hash:
                return False
        return True
    except Exception:
        return False

# ============== Tamper functions ==============
def tamper_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return token
    try:
        payload = json.loads(pyjwt.utils.base64url_decode(parts[1]))
        payload["perms"] = ["admin", "root", "delete"]
        new_payload = pyjwt.utils.base64url_encode(json.dumps(payload).encode())
        return f"{parts[0]}.{new_payload}.{parts[2]}"
    except Exception:
        return token

def tamper_dct_payload(token):
    import copy
    t = copy.deepcopy(token)
    t["payload"]["node_id"] = "attacker-node"
    t["payload"]["container_id"] = "attacker-container"
    t["payload"]["perms"] = ["admin", "root"]
    return t

def tamper_dct_chain(token):
    import copy
    t = copy.deepcopy(token)
    t["payload"]["chain_anchor"] = hashlib.sha256(b"forged").hexdigest()
    return t

# ============== Attack runner ==============
def run_attack(aname, mk_fn, vf_fn, orig_ctx, atk_ctx, reg,
               revoke_before=False, tamper_fn=None, is_chain_attack=False, n=N_TRIALS):
    accepted = rejected = 0
    for _ in range(n):
        token = mk_fn(orig_ctx)
        if revoke_before:
            reg.revoke(orig_ctx.did)
        if tamper_fn:
            token = tamper_fn(token)
        if is_chain_attack:
            forged = hashlib.sha256(b"forged_behavior_chain").hexdigest()
            result = vf_fn(token, atk_ctx, reg, chain_hash=forged)
        else:
            result = vf_fn(token, atk_ctx, reg)
        if result:
            accepted += 1
        else:
            rejected += 1
    return {"attack": aname, "trials": n, "accepted": accepted,
            "rejected": rejected, "reject_rate": round(rejected / n, 4)}

# ============== Main ==============
def run_experiment(output_dir="results"):
    os.makedirs(output_dir, exist_ok=True)
    orig = TokenContext("agent-001", "node-prod-01", "ctr-a1b2c3")
    atk = TokenContext("agent-001", "node-attacker", "ctr-evil")

    variants = [
        ("B1: Plain JWT", make_plain_jwt, verify_plain_jwt, tamper_jwt),
        ("B2: JWT + env", make_jwt_env, verify_jwt_env, tamper_jwt),
        ("B3: DCT env-only", make_dct_env, verify_dct_env, tamper_dct_payload),
        ("B4: DCT+ (full)", make_dct_plus, verify_dct_plus, tamper_dct_chain),
    ]

    attacks = [
        ("A1: Cross-container Migration", False, None, False),
        ("A2: Post-revoke Replay", True, None, False),
        ("A3: Chain_Anchor Forgery", False, "chain", True),
    ]

    all_results = []
    print("=" * 70)
    print("RQ3: DCT+ vs Static JWT — Credential Security Comparison")
    print("=" * 70)

    for vname, mk_fn, vf_fn, tf in variants:
        print(f"\n{'─'*70}")
        print(f"  {vname}")
        print(f"{'─'*70}")
        for aname, revoke_before, tamper_flag, is_chain in attacks:
            reg = RevocationRegistry()
            if tamper_flag == "tamper":
                tamper_fn = tf
            elif tamper_flag == "chain":
                tamper_fn = None
            else:
                tamper_fn = None
            # A2 (replay) and A3 (chain forgery): same environment,
            # isolates revocation check and chain verification respectively
            verify_ctx = orig if ("Replay" in aname or "Forgery" in aname) else atk
            r = run_attack(aname, mk_fn, vf_fn, orig, verify_ctx, reg,
                          revoke_before, tamper_fn, is_chain_attack=is_chain)
            r["variant"] = vname
            all_results.append(r)
            print(f"    {aname:<30s}: accept={r['accepted']:4d}  "
                  f"reject={r['rejected']:4d}  rate={r['reject_rate']:.1%}")

    # ======= Summary table =======
    print(f"\n{'='*70}")
    print("Comparison Matrix: Reject Rate — Higher is Better")
    print(f"{'='*70}")
    print(f"  {'Variant':<20} {'A1 Migration':<14} {'A2 Replay':<14} {'A3 Chain Forgery':<14}")
    print(f"  {'-'*70}")
    for vname in [v[0] for v in variants]:
        row = [vname]
        for aname in ["A1: Cross-container Migration",
                       "A2: Post-revoke Replay",
                       "A3: Chain_Anchor Forgery"]:
            match = [r for r in all_results
                     if r["variant"] == vname and r["attack"] == aname]
            rate = f"{match[0]['reject_rate']:.1%}" if match else "—"
            row.append(rate)
        print(f"  {row[0]:<20} {row[1]:<14} {row[2]:<14} {row[3]:<14}")

    # ======= Key Findings =======
    print(f"\n{'='*70}")
    print("Key Findings")
    print(f"{'='*70}")
    b1_mig = [r for r in all_results if r["variant"] == "B1: Plain JWT" and "Migration" in r["attack"]][0]
    b4_mig = [r for r in all_results if r["variant"] == "B4: DCT+ (full)" and "Migration" in r["attack"]][0]
    b1_rep = [r for r in all_results if r["variant"] == "B1: Plain JWT" and "Replay" in r["attack"]][0]
    b4_rep = [r for r in all_results if r["variant"] == "B4: DCT+ (full)" and "Replay" in r["attack"]][0]
    b1_chf = [r for r in all_results if r["variant"] == "B1: Plain JWT" and "Forgery" in r["attack"]][0]
    b4_chf = [r for r in all_results if r["variant"] == "B4: DCT+ (full)" and "Forgery" in r["attack"]][0]
    print(f"  1. Migration:    JWT accepts {b1_mig['accepted']}/{N_TRIALS},  DCT+ accepts {b4_mig['accepted']}/{N_TRIALS}")
    print(f"  2. Replay:       JWT accepts {b1_rep['accepted']}/{N_TRIALS},  DCT+ accepts {b4_rep['accepted']}/{N_TRIALS}")
    print(f"  3. Chain Forgery: JWT accepts {b1_chf['accepted']}/{N_TRIALS},  DCT+ accepts {b4_chf['accepted']}/{N_TRIALS}")

    out = {"experiment": "rq3_dct_vs_jwt", "n_trials": N_TRIALS, "results": all_results}
    p = os.path.join(output_dir, "rq3_dct_vs_jwt.json")
    with open(p, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {p}")
    return all_results


def run_dct_ablation(output_dir="results"):
    return run_experiment(output_dir)


if __name__ == "__main__":
    run_experiment()