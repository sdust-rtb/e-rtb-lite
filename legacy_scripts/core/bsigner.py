"""
BSigner - E-RTB-Lite 核心签名机模块

实现CBA-Lite协议的三项核心校验：
  A) 通道MAC验证（HMAC-SHA256）    → 抵御事件篡改
  B) 序列号连续性校验（严格单调递增）→ 抵御重放与乱序
  C) 哈希链递推 + Ed25519签名       → 抵御历史篡改与签名伪造

TCB边界：本模块内的核心逻辑即为E-RTB-Lite的全部密码学信任根。
"""

import os
import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Tuple, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class MACVerificationError(ValueError):
    """校验A失败：通道MAC不匹配（敌手无法获取channel_key）"""
    pass


class SequenceMismatchError(ValueError):
    """校验B失败：序列号不连续（敌手截获旧事件重放）"""
    pass


class HashChainError(ValueError):
    """校验C失败：哈希链断裂（敌手篡改历史证据）"""
    pass


@dataclass
class BehaviorEvent:
    """行为事件：eBPF探针捕获的单条syscall特征向量 a_t"""
    syscall_type: str
    target_resource: str
    parameters: str
    timestamp_ns: int = field(default_factory=time.time_ns)

    def feature_bytes(self) -> bytes:
        return f"{self.syscall_type}|{self.target_resource}|{self.parameters}".encode()


@dataclass
class EvidencePackage:
    """签名证据包 E_t = <h_curr, seq, sigma_t>"""
    h_curr: bytes
    seq: int
    sigma: bytes
    timestamp: float = field(default_factory=time.time)


class BSigner:
    """
    透明签名机（唯一TCB组件）

    内部持久化状态：
      h_prev      (32B)  哈希链当前状态
      h0          (32B)  哈希链初始锚点（签名前保存，供离线验证）
      seq_exp     (8B)   期望的下一个序列号
      SK_Agent    Ed25519私钥
      PK_Agent    Ed25519公钥（派生）
      channel_key (32B)  eBPF↔签名机 HMAC共享密钥
    """

    def __init__(self, did: str = "default_DID",
                 node_id: str = "default_Node",
                 container_id: str = "default_Container",
                 channel_key: Optional[bytes] = None,
                 private_key_bytes: Optional[bytes] = None):
        if private_key_bytes:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        seed = os.urandom(32)
        self.h_prev = hashlib.sha256(
            f"{did}|{node_id}|{container_id}|".encode() + seed
        ).digest()
        self.h0 = bytes(self.h_prev)

        self.seq_exp: int = 0
        self.channel_key = channel_key or os.urandom(32)
        self.sign_count = 0

    def get_public_key_bytes(self) -> bytes:
        """导出公钥字节（供验证方使用）"""
        return self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def get_private_key_bytes(self) -> bytes:
        """导出私钥字节（供崩溃恢复时持久化）"""
        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def get_h0(self) -> bytes:
        return self.h0

    def generate_channel_mac(self, event: BehaviorEvent, seq: int) -> bytes:
        msg = event.feature_bytes() + seq.to_bytes(8, "big")
        return hmac.new(self.channel_key, msg, hashlib.sha256).digest()

    def verify_and_sign(
        self, event: BehaviorEvent, channel_mac: bytes, seq: int,
    ) -> EvidencePackage:
        expected_mac = hmac.new(
            self.channel_key,
            event.feature_bytes() + seq.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(channel_mac, expected_mac):
            raise MACVerificationError("FAIL_A: channel MAC verification failed")

        if seq != self.seq_exp:
            raise SequenceMismatchError(
                f"FAIL_B: seq mismatch (expected {self.seq_exp}, got {seq})"
            )

        h_curr = hmac.new(
            self.h_prev,
            event.feature_bytes() + seq.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()

        ts_int = int(time.time())
        ts = ts_int.to_bytes(8, "big")
        sigma = self._private_key.sign(h_curr + seq.to_bytes(8, "big") + ts)

        self.h_prev = h_curr
        self.seq_exp += 1
        self.sign_count += 1

        return EvidencePackage(h_curr=h_curr, seq=seq, sigma=sigma, timestamp=float(ts_int))

    @staticmethod
    def verify_evidence(pkg: EvidencePackage, public_key_bytes: bytes) -> bool:
        pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        ts = int(pkg.timestamp).to_bytes(8, "big")
        try:
            pk.verify(pkg.sigma, pkg.h_curr + pkg.seq.to_bytes(8, "big") + ts)
            return True
        except Exception:
            return False

    def batch_sign(
        self, events: List[BehaviorEvent], noisy: bool = False
    ) -> Tuple[List[EvidencePackage], List[BehaviorEvent]]:
        packages, signed_events = [], []
        for i, event in enumerate(events):
            mac = self.generate_channel_mac(event, i)
            if noisy:
                mac = os.urandom(32)
            try:
                pkg = self.verify_and_sign(event, mac, i)
                packages.append(pkg)
                signed_events.append(event)
            except ValueError:
                pass
        return packages, signed_events
