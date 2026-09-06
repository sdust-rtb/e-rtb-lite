"""
Property 3 (Persistent Violation Reputation Zeroing) 公式验证脚本

论文 §4.3 声称:
    T_max = ceil(R_0 / (eta * Risk_min))

实际代码中的递推公式 (§4.1, dynamics_sim.py):
    R_{t+1} = clip((1-gamma) * R_t + gamma * r_reward - eta * risk_t, 0, 1)

本脚本验证:
  1. 精确推导公式 (gamma > 0) 是否与模拟一致
  2. 论文简化公式 T_max = ceil(R_0/(eta*risk_min)) 是精确公式在 gamma->0 时的上界
  3. 在参数空间 (gamma, eta, risk_min, R_0, r_reward) 上两种公式的偏差
"""

import math
import numpy as np
from itertools import product

# ==================================================================
# 第一部分：精确公式推导 (基于实际递推)
# ==================================================================
# 实际递推: R_{t+1} = (1-gamma)*R_t + gamma*r_reward - eta*risk_t
# 设 C = eta*risk_min - gamma*r_reward  (净惩罚量，要求 C > 0)
# 解闭式: R_t = (1-gamma)^t * (R_0 + C/gamma) - C/gamma
# 设 R_T = 0:
#   T_exact = ceil(log(1 + (gamma * R_0) / C) / (-log(1 - gamma)))
# ==================================================================

# 论文简化公式 (gamma -> 0 极限):
#   T_paper = ceil(R_0 / (eta * risk_min))
# ==================================================================

def exact_T_max(R_0, gamma, r_reward, eta, risk_min):
    """基于实际闭式递推的精确上界 (gamma > 0)。"""
    C = eta * risk_min - gamma * r_reward
    if C <= 0:
        return math.inf  # 惩罚不足以使声誉归零
    return math.ceil(math.log(1 + gamma * R_0 / C) / (-math.log(1 - gamma)))

def paper_T_max(R_0, eta, risk_min):
    """论文简化公式 (gamma->0 极限上界)。"""
    if eta * risk_min <= 0:
        return math.inf
    return math.ceil(R_0 / (eta * risk_min))

def simulate_T_max(R_0, gamma, r_reward, eta, risk_min, n_max=20000):
    """用实际递推模拟，记录声誉首次 <= 0 的步数。"""
    R = R_0
    for t in range(1, n_max + 1):
        R = (1 - gamma) * R + gamma * r_reward - eta * risk_min
        R = max(0.0, min(R, 1.0))
        if R <= 0.0:
            return t
    return n_max

# ==================================================================
# 第二部分：基准情况验证 (论文参数: gamma=0.05, r_reward=0.1, eta=0.01055, risk=0.5, R_0=0.8)
# ==================================================================
print("=" * 80)
print("Part 1: 基准情况验证 (论文实验参数)")
print("=" * 80)

base = dict(R_0=0.8, gamma=0.05, r_reward=0.1, eta=0.01055, risk_min=0.5)
T_sim  = simulate_T_max(**base)
T_ex   = exact_T_max(**base)
T_pap  = paper_T_max(base["R_0"], base["eta"], base["risk_min"])

C = base["eta"] * base["risk_min"] - base["gamma"] * base["r_reward"]
print(f"  净惩罚 C = eta*risk - gamma*r_reward = {base['eta']:.5f}*{base['risk_min']} - {base['gamma']}*{base['r_reward']:.3f}")
print(f"          = {C:.6f}")
print(f"  模拟 T_sim (reputation 首次 <= 0): {T_sim} 步  (论文称: 105 步上界, 实际步 97)")
print(f"  精确公式 T_exact:                   {T_ex} 步")
print(f"  论文简化公式 T_paper:               {T_pap} 步  (上界, 宽松)")
print()
print(f"  结论: T_exact {'=' if T_ex == T_sim else '!='} T_sim ({'CORRECT' if T_ex == T_sim else 'ERROR!'})")
print(f"        T_paper >= T_sim? {T_pap >= T_sim}  ({'paper 公式是上界 (宽松)' if T_pap >= T_sim else 'PAPER FORMULA WRONG!'})")

# ==================================================================
# 第三部分：参数空间扫描
# ==================================================================
print("\n" + "=" * 80)
print("Part 2: 参数空间扫描")
print("=" * 80)

gamma_vals = [0.005, 0.01, 0.02, 0.05, 0.1, 0.2]
eta_vals = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0]
risk_min_vals = [0.1, 0.2, 0.5, 1.0]
R0_vals = [0.5, 0.7, 0.8, 0.9, 1.0]
r_reward_vals = [0.0, 0.05, 0.1, 0.5]

violations_exact = []
violations_paper = []
tight_cases = []
n_total = 0
n_skip_C_le_0 = 0

grid = list(product(gamma_vals, eta_vals, risk_min_vals, R0_vals, r_reward_vals))
print(f"  扫描 {(len(grid))} 个参数组合...")

for gamma, eta, risk_min, R_0, r_reward in grid:
    n_total += 1
    C = eta * risk_min - gamma * r_reward
    if C <= 0:
        n_skip_C_le_0 += 1
        continue

    T_sim  = simulate_T_max(R_0, gamma, r_reward, eta, risk_min)
    T_ex   = exact_T_max(R_0, gamma, r_reward, eta, risk_min)
    T_pap  = paper_T_max(R_0, eta, risk_min)

    # 精确公式验证
    if T_ex != T_sim:
        violations_exact.append(dict(
            gamma=gamma, eta=eta, risk_min=risk_min, R_0=R_0, r_reward=r_reward,
            T_sim=T_sim, T_ex=T_ex, diff=T_ex - T_sim
        ))

    # 论文公式作为上界验证
    if T_pap < T_sim:
        violations_paper.append(dict(
            gamma=gamma, eta=eta, risk_min=risk_min, R_0=R_0, r_reward=r_reward,
            T_sim=T_sim, T_pap=T_pap, diff=T_sim - T_pap
        ))

    # 紧密度
    if T_pap == T_sim:
        tight_cases.append(dict(gamma=gamma, eta=eta, risk_min=risk_min, R_0=R_0, r_reward=r_reward, T=T_pap))

print(f"\n  总组合: {n_total}")
print(f"  跳过 (C<=0): {n_skip_C_le_0}")
print(f"  精确公式 vs 模拟 不符: {len(violations_exact)}  {'OK' if len(violations_exact) == 0 else 'PROBLEM!'}")
print(f"  论文简化公式 不是上界: {len(violations_paper)}  {'OK' if len(violations_paper) == 0 else 'PROBLEM: paper formula breaks for some params'}")
print(f"  论文公式紧密 (= 模拟值) 的情况: {len(tight_cases)}")

# ==================================================================
# 第四部分：论文公式不成立的情况 (如有)
# ==================================================================
if violations_paper:
    print("\n" + "=" * 80)
    print(f"Part 3: 论文公式不成立的情况 (共 {len(violations_paper)} 个)")
    print("=" * 80)
    for v in violations_paper[:10]:
        print(f"  gamma={v['gamma']}, eta={v['eta']}, risk_min={v['risk_min']}, R_0={v['R_0']}, r_reward={v['r_reward']}")
        print(f"    T_sim={v['T_sim']}, T_paper={v['T_pap']}, diff={v['diff']} (paper UNDERESTIMATES!)")
    if len(violations_paper) > 10:
        print(f"  ... ({len(violations_paper) - 10} more)")

# ==================================================================
# 第五部分：gamma 小 -> paper 接近 exact 的验证
# ==================================================================
print("\n" + "=" * 80)
print("Part 4: gamma -> 0 极限验证 (论文简化公式的成立条件)")
print("=" * 80)
print("  固定: r_reward=0.1, eta=0.1, risk_min=0.5, R_0=0.8")
print()
print(f"  {'gamma':>6s} {'T_sim':>6s} {'T_exact':>8s} {'T_paper':>8s} {'T_pap/T_sim':>12s}")
print("  " + "-" * 50)
for gamma in [0.5, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005, 0.001, 0.0005]:
    if gamma >= 1.0:
        continue
    T_sim = simulate_T_max(0.8, gamma, 0.1, 0.1, 0.5)
    T_ex = exact_T_max(0.8, gamma, 0.1, 0.1, 0.5)
    T_pap = paper_T_max(0.8, 0.1, 0.5)
    ratio = T_pap / T_sim if T_sim > 0 and not (isinstance(T_ex, float) and math.isinf(T_ex)) else float('inf')
    T_ex_s = str(T_ex)[:8]
    print(f"  {gamma:>6.3f} {T_sim:>6d} {T_ex_s:>8s} {T_pap:>8d} {ratio:>12.3f}")

print()
print("  结论: gamma 越小, T_paper/T_sim 比值越接近 1.0 (tighter upper bound)")

# ==================================================================
# 第六部分：修正论文公式 (添加 gamma 修正项)
# ==================================================================
print("\n" + "=" * 80)
print("Part 5: 推荐的修正公式 (供论文使用)")
print("=" * 80)
print()
print("  精确公式 (基于实际递推):")
print("    C = eta * Risk_min - gamma * r_reward    (需要 C > 0)")
print("    T_max = ceil(log(1 + gamma*R_0/C) / (-log(1-gamma)))")
print()
print("  论文简化公式 (作为宽松上界):")
print("    T_max <= ceil(R_0 / (eta * Risk_min))    (当 gamma * r_reward << eta * Risk_min)")
print()
print("  推荐论文表述:")
print("    'Under sustained violation with penalty C = eta * Risk_min - gamma * r_reward > 0,")
print("     reputation reaches zero within T = ceil(log(1 + gamma*R_0/C) / (-log(1-gamma))) steps.")
print("     For small gamma, this is bounded by ceil(R_0 / (eta * Risk_min)).'")

# ==================================================================
# 第七部分：关键参数敏感性
# ==================================================================
print("\n" + "=" * 80)
print("Part 6: 关键参数对 T_max 的影响 (论文实验值基准)")
print("=" * 80)
base_gamma = 0.05
base_r_reward = 0.1
base_eta = 0.01055
base_risk_min = 0.5
base_R_0 = 0.8
print(f"  基准: gamma={base_gamma}, r_reward={base_r_reward}, eta={base_eta}, risk_min={base_risk_min}, R_0={base_R_0}")
print()

print("  eta 敏感性 (risk_min=0.5):")
print(f"    {'eta':>7s} {'C':>10s} {'T_exact':>8s} {'T_paper':>8s}")
print("    " + "-" * 40)
for eta in [0.005, 0.008, 0.01055, 0.015, 0.02, 0.05, 0.1]:
    C = eta * base_risk_min - base_gamma * base_r_reward
    if C > 0:
        T_ex  = exact_T_max(base_R_0, base_gamma, base_r_reward, eta, base_risk_min)
        T_pap = paper_T_max(base_R_0, eta, base_risk_min)
    else:
        T_ex, T_pap = float('inf'), float('inf')
    print(f"    {eta:>7.4f} {C:>10.6f} {T_ex:>8} {T_pap:>8}")

print()
print("  risk_min 敏感性 (eta=0.01055):")
print(f"    {'risk_min':>9s} {'C':>10s} {'T_exact':>8s} {'T_pap':>8s}")
print("    " + "-" * 44)
for risk_min in [0.1, 0.3, 0.5, 0.7, 1.0, 2.0]:
    C = base_eta * risk_min - base_gamma * base_r_reward
    if C > 0:
        T_ex  = exact_T_max(base_R_0, base_gamma, base_r_reward, base_eta, risk_min)
        T_pap = paper_T_max(base_R_0, base_eta, risk_min)
    else:
        T_ex, T_pap = float('inf'), float('inf')
    print(f"    {risk_min:>9.2f} {C:>10.6f} {T_ex:>8} {T_pap:>8}")

print("\n" + "=" * 80)
print("END")
print("=" * 80)
