"""
RQ2 模拟审计引擎（仅用于 --skip-api 调试模式）

不调用真实LLM API，仅用于测试实验流程的代码正确性。
实际实验必须使用 jury_quality.py 的 LLMJurorAPI。
"""

import random


class LLMAuditSimulator:
    """基于规则的模拟LLM审计员（非真实LLM，仅调试用）"""

    VIOLATION_KEYWORDS = [
        ("openat", "/etc"),
        ("execve", "/usr/bin/sudo"),
        ("tcp_v4_connect", "192.168"),
        ("tcp_sendmsg", "evil"),
        ("openat", "/root"),
    ]

    def __init__(self, model_name="sim", base_accuracy=0.85, seed=42):
        self.model_name = model_name
        self.base_accuracy = base_accuracy
        self.rng = random.Random(seed)
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0

    def audit(self, case_id: str, events: list, gold_label=None) -> dict:
        has_violation = any(
            any(kw[0] == e.get("syscall", "") and kw[1] in e.get("resource", "")
                for kw in self.VIOLATION_KEYWORDS)
            for e in events
        )

        if gold_label is not None:
            verdict = gold_label if self.rng.random() < self.base_accuracy else 1 - gold_label
        else:
            verdict = 1 if has_violation else 0

        self.call_count += 1
        return {
            "verdict": verdict,
            "engine": self.model_name,
            "thought_trace": f"[SIM {self.model_name}] verdict={'violation' if verdict else 'compliant'}",
            "rule_violations": [],
        }

    @property
    def cost_rmb(self) -> float:
        return 0.0

    @property
    def label(self):
        return self.model_name
