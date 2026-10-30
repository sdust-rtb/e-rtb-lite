"""
bsigner 单元测试

覆盖：
  - 正常签名流程
  - 校验A失败（MAC伪造）
  - 校验B失败（序列号不匹配）
  - h0 保存正确性
  - 离线签名验证
  - 哈希链完整性
  - 批量签名
  - 边界情况（空事件、极长资源名）

运行：pytest tests/test_bsigner.py -v
"""

import os
import sys
import hmac
import hashlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.bsigner import (
    BSigner, BehaviorEvent, EvidencePackage,
    MACVerificationError, SequenceMismatchError,
)


class TestBSignerInit:
    def test_creates_with_defaults(self):
        bs = BSigner()
        assert bs.seq_exp == 0
        assert bs.sign_count == 0
        assert len(bs.channel_key) == 32
        assert len(bs.h_prev) == 32

    def test_h0_saved_correctly(self):
        bs = BSigner()
        h0 = bs.get_h0()
        assert len(h0) == 32
        # h0 应该等于初始化后的 h_prev（签名前）
        assert h0 == bs.h_prev

    def test_h0_unchanged_after_signing(self):
        bs = BSigner()
        h0_before = bs.get_h0()
        # 签名一条事件
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        bs.verify_and_sign(e, mac, 0)
        # h0 不应变化
        assert bs.get_h0() == h0_before
        # 但 h_prev 应该变了
        assert bs.h_prev != h0_before

    def test_public_key_not_empty(self):
        bs = BSigner()
        pk = bs.get_public_key_bytes()
        assert len(pk) == 32  # Ed25519 public key = 32 bytes

    def test_different_instances_different_keys(self):
        bs1 = BSigner()
        bs2 = BSigner()
        assert bs1.get_public_key_bytes() != bs2.get_public_key_bytes()
        assert bs1.channel_key != bs2.channel_key


class TestChannelMAC:
    def test_mac_deterministic(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/etc/passwd", "O_RDONLY")
        mac1 = bs.generate_channel_mac(e, 0)
        mac2 = bs.generate_channel_mac(e, 0)
        assert mac1 == mac2

    def test_mac_depends_on_event(self):
        bs = BSigner()
        e1 = BehaviorEvent("openat", "/etc/passwd", "O_RDONLY")
        e2 = BehaviorEvent("execve", "/bin/bash", "")
        assert bs.generate_channel_mac(e1, 0) != bs.generate_channel_mac(e2, 0)

    def test_mac_depends_on_seq(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        assert bs.generate_channel_mac(e, 0) != bs.generate_channel_mac(e, 1)

    def test_mac_length(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        assert len(mac) == 32  # SHA256 = 32 bytes


class TestVerifyAndSign:
    def test_normal_sign_succeeds(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/app/data/config.json", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        assert isinstance(pkg, EvidencePackage)
        assert pkg.seq == 0
        assert len(pkg.h_curr) == 32
        assert len(pkg.sigma) == 64  # Ed25519 signature = 64 bytes
        assert bs.seq_exp == 1
        assert bs.sign_count == 1

    def test_sequence_increments(self):
        bs = BSigner()
        for i in range(10):
            e = BehaviorEvent("read", f"/file/{i}", "ok")
            mac = bs.generate_channel_mac(e, i)
            pkg = bs.verify_and_sign(e, mac, i)
            assert pkg.seq == i
        assert bs.seq_exp == 10
        assert bs.sign_count == 10

    def test_fail_a_mac_forgery(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/etc/shadow", "O_RDONLY")
        fake_mac = os.urandom(32)
        with pytest.raises(MACVerificationError, match="FAIL_A"):
            bs.verify_and_sign(e, fake_mac, 0)

    def test_fail_a_wrong_key(self):
        bs1 = BSigner()
        bs2 = BSigner()  # 不同的channel_key
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs1.generate_channel_mac(e, 0)
        with pytest.raises(MACVerificationError):
            bs2.verify_and_sign(e, mac, 0)

    def test_fail_b_seq_mismatch(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        # 期望 seq=0，提交 seq=5
        mac = bs.generate_channel_mac(e, 5)
        with pytest.raises(SequenceMismatchError, match="FAIL_B"):
            bs.verify_and_sign(e, mac, 5)

    def test_fail_b_replay(self):
        bs = BSigner()
        e1 = BehaviorEvent("openat", "/file1", "O_RDONLY")
        mac1 = bs.generate_channel_mac(e1, 0)
        bs.verify_and_sign(e1, mac1, 0)

        # 尝试重放 seq=0
        e2 = BehaviorEvent("openat", "/file2", "O_RDONLY")
        mac0 = bs.generate_channel_mac(e2, 0)
        with pytest.raises(SequenceMismatchError):
            bs.verify_and_sign(e2, mac0, 0)

    def test_empty_resource(self):
        bs = BSigner()
        e = BehaviorEvent("execve", "", "")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        assert pkg.seq == 0

    def test_long_resource(self):
        bs = BSigner()
        long_path = "/a" * 1000
        e = BehaviorEvent("openat", long_path, "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        assert pkg.seq == 0


class TestVerifyEvidence:
    def test_valid_signature(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        assert BSigner.verify_evidence(pkg, bs.get_public_key_bytes())

    def test_tampered_h_curr(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        # 篡改 h_curr
        tampered = EvidencePackage(
            h_curr=os.urandom(32), seq=pkg.seq,
            sigma=pkg.sigma, timestamp=pkg.timestamp,
        )
        assert not BSigner.verify_evidence(tampered, bs.get_public_key_bytes())

    def test_tampered_seq(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        tampered = EvidencePackage(
            h_curr=pkg.h_curr, seq=999,
            sigma=pkg.sigma, timestamp=pkg.timestamp,
        )
        assert not BSigner.verify_evidence(tampered, bs.get_public_key_bytes())

    def test_wrong_public_key(self):
        bs1 = BSigner()
        bs2 = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs1.generate_channel_mac(e, 0)
        pkg = bs1.verify_and_sign(e, mac, 0)
        # 用错误的公钥验证
        assert not BSigner.verify_evidence(pkg, bs2.get_public_key_bytes())

    def test_forged_signature(self):
        bs = BSigner()
        e = BehaviorEvent("openat", "/tmp/test", "O_RDONLY")
        mac = bs.generate_channel_mac(e, 0)
        pkg = bs.verify_and_sign(e, mac, 0)
        forged = EvidencePackage(
            h_curr=pkg.h_curr, seq=pkg.seq,
            sigma=os.urandom(64), timestamp=pkg.timestamp,
        )
        assert not BSigner.verify_evidence(forged, bs.get_public_key_bytes())


class TestBatchSign:
    def test_batch_normal(self):
        bs = BSigner()
        events = [
            BehaviorEvent("openat", f"/file/{i}", "O_RDONLY")
            for i in range(100)
        ]
        packages, signed = bs.batch_sign(events)
        assert len(packages) == 100
        assert len(signed) == 100
        assert bs.sign_count == 100

    def test_batch_with_noise(self):
        bs = BSigner()
        events = [
            BehaviorEvent("openat", f"/file/{i}", "O_RDONLY")
            for i in range(100)
        ]
        packages, signed = bs.batch_sign(events, noisy=True)
        # noisy模式下MAC全部伪造，应全部失败
        assert len(packages) == 0
        assert bs.sign_count == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
