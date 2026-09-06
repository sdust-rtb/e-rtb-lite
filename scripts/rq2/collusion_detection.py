"""
RQ2 共谋检测精度评估

对应论文 §5.4.1：验证语义共谋检测（余弦相似度 + 裁决方向硬约束）
将共谋检测精确率从基线提升至目标值。

数据: data/collusion_pairs.json (100对, 由 core/data_gen.py 生成)
输出: results/rq2_collusion_results.json
"""

import os
import sys
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """计算两个向量的余弦相似度"""
    a, b = np.array(a), np.array(b)
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom < 1e-12:
        return 0.0
    return float(np.dot(a, b) / denom)


def simple_embed(text: str, dim: int = 128) -> List[float]:
    """
    特征嵌入函数：基于字符级n-gram + 词汇特征的混合向量
    生产环境可替换为 sentence-transformer 模型以获得更高精度
    """
    import hashlib
    vec = np.zeros(dim)
    text_lower = text.lower()
    words = text_lower.split()

    # 词汇级特征（关键词权重加权）
    security_keywords = {
        "violation": 3.0, "unauthorized": 3.0, "malicious": 2.5,
        "suspicious": 2.0, "attack": 2.5, "exploit": 2.5,
        "shadow": 2.0, "sudo": 2.0, "exfil": 3.0, "credential": 2.0,
        "compliant": 2.0, "legitimate": 2.0, "normal": 1.5, "routine": 1.5,
        "confirmed": 1.5, "denied": 1.5, "access": 1.0, "read": 0.5,
        "process": 0.5, "system": 0.5, "file": 0.5,
    }
    for i, w in enumerate(words):
        base_weight = security_keywords.get(w, 0.3)
        h = int(hashlib.md5(w.encode()).hexdigest(), 16)
        for j in range(dim):
            vec[j] += base_weight * (((h >> (j % 32)) & 1) * 2.0 - 1.0)

    # 字符级 bigram 特征（捕获句式相似性）
    for i in range(len(text_lower) - 1):
        bigram = text_lower[i:i+2]
        h = int(hashlib.md5(bigram.encode()).hexdigest(), 16)
        idx = h % dim
        vec[idx] += 0.5

    norm = np.linalg.norm(vec)
    return (vec / norm).tolist() if norm > 1e-12 else vec.tolist()


def evaluate_collusion_detection(
    pairs: List[Dict],
    similarity_threshold: float = 0.50,
    verdict_constraint: bool = True,
) -> Dict:
    """
    评估共谋检测性能

    Args:
        pairs: 共谋/非共谋案件对列表，每项包含:
            thought_trace_a, thought_trace_b, verdict_a, verdict_b, is_collusion
        similarity_threshold: 判定共谋的余弦相似度阈值
        verdict_constraint: 是否启用裁决方向硬约束
            (裁决方向相反时相似度直接置0)

    Returns:
        {"precision": ..., "recall": ..., "f1": ...,
         "tp": ..., "fp": ..., "tn": ..., "fn": ...}
    """
    tp = fp = tn = fn = 0

    for pair in pairs:
        sim = cosine_similarity(
            simple_embed(pair.get("trace_a", pair.get("thought_trace_a", ""))),
            simple_embed(pair.get("trace_b", pair.get("thought_trace_b", ""))),
        )

        # 裁决方向硬约束
        if verdict_constraint and pair["verdict_a"] != pair["verdict_b"]:
            sim = 0.0

        predicted_collusion = sim >= similarity_threshold
        actual_collusion = pair["is_collusion"]

        if predicted_collusion and actual_collusion:
            tp += 1
        elif predicted_collusion and not actual_collusion:
            fp += 1
        elif not predicted_collusion and not actual_collusion:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "threshold": similarity_threshold,
        "verdict_constraint": verdict_constraint,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def run_collusion_eval(output_dir: str):
    """
    包装函数，供 run_all.py 统一调用

    Args:
        output_dir: results 目录路径
    """
    root = Path(__file__).resolve().parent.parent
    data_path = root / "data" / "collusion_pairs.json"
    results_dir = Path(output_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    if not data_path.exists():
        print(f"  [SKIP] 数据文件不存在: {data_path}")
        print(f"         请先运行 core/data_gen.py")
        return None

    with open(data_path, "r", encoding="utf-8") as f:
        pairs = json.load(f)

    print(f"  加载 {len(pairs)} 对共谋/非共谋案件")

    baseline = evaluate_collusion_detection(pairs, verdict_constraint=False)
    constrained = evaluate_collusion_detection(pairs, verdict_constraint=True)

    delta = constrained["precision"] - baseline["precision"]
    print(f"  基线 Precision={baseline['precision']:.4f}  "
          f"F1={baseline['f1']:.4f}")
    print(f"  硬约束 Precision={constrained['precision']:.4f}  "
          f"F1={constrained['f1']:.4f}")
    print(f"  精确率提升: {baseline['precision']:.4f} -> "
          f"{constrained['precision']:.4f}  (delta={delta:+.4f})")

    import time as _time
    output = {
        "experiment": "rq2_collusion_detection",
        "n_pairs": len(pairs),
        "baseline": baseline,
        "with_verdict_constraint": constrained,
        "delta_precision": round(delta, 4),
    }
    out_path = results_dir / f"rq2_collusion_{_time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  结果已保存: {out_path}")
    return output


def main():
    root = Path(__file__).resolve().parent.parent
    data_path = root / "data" / "collusion_pairs.json"
    results_dir = root / "results"
    results_dir.mkdir(exist_ok=True)

    if not data_path.exists():
        print(f"[ERROR] 数据文件不存在: {data_path}")
        print("  请先运行 core/data_gen.py 生成数据")
        sys.exit(1)

    with open(data_path, "r", encoding="utf-8") as f:
        pairs = json.load(f)

    print(f"[共谋检测实验] 加载 {len(pairs)} 对数据")

    # 基线：无裁决方向硬约束
    baseline = evaluate_collusion_detection(pairs, verdict_constraint=False)
    print(f"\n基线 (无硬约束):")
    print(f"  Precision={baseline['precision']:.4f}  "
          f"Recall={baseline['recall']:.4f}  F1={baseline['f1']:.4f}")
    print(f"  TP={baseline['tp']} FP={baseline['fp']} "
          f"TN={baseline['tn']} FN={baseline['fn']}")

    # 启用裁决方向硬约束
    constrained = evaluate_collusion_detection(pairs, verdict_constraint=True)
    print(f"\n启用裁决方向硬约束:")
    print(f"  Precision={constrained['precision']:.4f}  "
          f"Recall={constrained['recall']:.4f}  F1={constrained['f1']:.4f}")
    print(f"  TP={constrained['tp']} FP={constrained['fp']} "
          f"TN={constrained['tn']} FN={constrained['fn']}")

    delta_precision = constrained['precision'] - baseline['precision']
    print(f"\n精确率提升: {baseline['precision']:.4f} → {constrained['precision']:.4f}  "
          f"(Δ={delta_precision:+.4f})")

    # 多阈值扫描找最优 τ
    print(f"\n多阈值扫描:")
    best_f1, best_tau = 0, 0
    for tau in np.arange(0.10, 1.01, 0.05):
        r = evaluate_collusion_detection(pairs, similarity_threshold=round(tau, 2),
                                          verdict_constraint=True)
        if r['f1'] > best_f1:
            best_f1, best_tau = r['f1'], tau
        print(f"  τ={tau:.2f}  P={r['precision']:.4f}  R={r['recall']:.4f}  F1={r['f1']:.4f}")

    print(f"\n最优 τ={best_tau:.2f} (F1={best_f1:.4f})")

    output = {
        "experiment": "rq2_collusion_detection",
        "n_pairs": len(pairs),
        "baseline": baseline,
        "with_verdict_constraint": constrained,
        "delta_precision": round(delta_precision, 4),
        "optimal_tau": round(best_tau, 2),
        "optimal_f1": round(best_f1, 4),
    }

    import time
    out_path = results_dir / f"rq2_collusion_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n结果已保存: {out_path}")
    return output


if __name__ == "__main__":
    main()