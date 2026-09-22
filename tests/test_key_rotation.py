"""场景一：签名密钥轮换重叠窗口、未知 kid 受控重载、拒绝原因可区分。"""
from __future__ import annotations

import datetime as dt
import threading

import pytest

from ztauth.errors import AuthError, DenyReason
from ztauth.keys import KeyRing, SigningKey
from ztauth.sources import MutableKeySource
from ztauth.tokens import TokenIssuer, TokenVerifier


def test_overlap_window_both_keys_verify(ring, key_source, now):
    issuer = TokenIssuer(ring)
    verifier = TokenVerifier(ring)
    # 显式用旧 k1 签发（模拟轮换前已流通的令牌）
    t_old = issuer.issue("alice", ttl=dt.timedelta(minutes=5), kid="k1", now=now)
    # 默认用最新 active k2 签发
    t_new = issuer.issue("alice", ttl=dt.timedelta(minutes=5), now=now)
    assert verifier.verify(t_old, now=now).sub == "alice"
    assert verifier.verify(t_new, now=now).sub == "alice"


def test_old_key_after_window_is_rejected(ring, now):
    # k1 在 now+1d 退出窗口，之后其令牌按签名不匹配拒绝
    future = now + dt.timedelta(days=2)
    issuer = TokenIssuer(ring)
    token = issuer.issue("alice", ttl=dt.timedelta(days=10), kid="k1", now=now)
    with pytest.raises(AuthError) as ei:
        TokenVerifier(ring).verify(token, now=future)
    assert ei.value.reason is DenyReason.TOKEN_SIGNATURE_MISMATCH
    assert "outside validity window" in (ei.value.detail or "")


def test_unknown_kid_triggers_controlled_reload_once(overlapping_keys, now):
    k3 = SigningKey(
        "k3", b"secret-three",
        now - dt.timedelta(minutes=1), now + dt.timedelta(days=10), "active",
    )
    # 本地 ring 只持有 k1/k2（源版本 1）
    src = MutableKeySource(list(overlapping_keys), version=1)
    gate_ring = KeyRing(src)
    # 其他副本刚把 k3 发布进密钥源（版本 2）
    src.set_keys(list(overlapping_keys) + [k3], version=2)

    # 用已知 k3 的另一环签发令牌
    issuer_ring = KeyRing(MutableKeySource(list(overlapping_keys) + [k3], 2))
    token = TokenIssuer(issuer_ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), kid="k3", now=now
    )

    verifier = TokenVerifier(gate_ring)
    baseline = src.load_count  # 构造期首次加载
    assert verifier.verify(token, now=now).sub == "alice"
    assert gate_ring.version() == 2
    assert src.load_count == baseline + 1  # 首次未知 kid -> 恰好一次受控重载
    # 之后 kid 已知：不得重复拉取，也不得出现短暂失效
    verifier.verify(token, now=now)
    assert src.load_count == baseline + 1


def test_unknown_kid_concurrent_reload_single_fetch(ring, key_source, now):
    k4 = SigningKey(
        "k4", b"secret-four",
        now - dt.timedelta(minutes=1), now + dt.timedelta(days=10), "active",
    )
    # 用已知 k4 的环签发令牌；验证环将独立地从"不认识 k4"开始
    key_source.set_keys(list(key_source._keys) + [k4], version=3)  # type: ignore[attr-defined]
    token = TokenIssuer(ring).issue("bob", ttl=dt.timedelta(minutes=5), kid="k4", now=now)
    # gate_ring 起步只持有 k1/k2
    src = MutableKeySource([
        SigningKey("k1", b"secret-one",
                   now - dt.timedelta(days=30), now + dt.timedelta(days=1), "retiring"),
        SigningKey("k2", b"secret-two",
                   now - dt.timedelta(hours=1), now + dt.timedelta(days=30), "active"),
    ], version=1)
    gate_ring = KeyRing(src)
    # 其他副本刚把 k4 发布进密钥源（版本 2）
    src.set_keys([
        SigningKey("k1", b"secret-one",
                   now - dt.timedelta(days=30), now + dt.timedelta(days=1), "retiring"),
        SigningKey("k2", b"secret-two",
                   now - dt.timedelta(hours=1), now + dt.timedelta(days=30), "active"),
        k4,
    ], version=2)
    verifier = TokenVerifier(gate_ring)
    baseline = src.load_count
    errors: list[Exception] = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        try:
            assert verifier.verify(token, now=now).sub == "bob"
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # single-flight：20 个并发未知 kid 只允许 1 次额外实际拉取
    assert src.load_count == baseline + 1


def test_unknown_kid_source_down_is_distinct_reason(overlapping_keys, now):
    """初始加载成功、受控重载时密钥源不可用：原因须区别于"未知 kid"。"""
    src = MutableKeySourceReloadFails(list(overlapping_keys), version=1)
    ring = KeyRing(src)
    # 手工伪造 kid=k9 的令牌头（签名无所谓：应先在 kid 解析处触发重载）
    issuer = TokenIssuer(ring)
    good = issuer.issue("c", ttl=dt.timedelta(minutes=1), kid="k1", now=now)
    h, c, s = good.split(".")
    import base64
    import json
    pad = "=" * (-len(h) % 4)
    header = json.loads(base64.urlsafe_b64decode(h + pad))
    header["kid"] = "k9"
    h2 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    forged = f"{h2}.{c}.{s}"
    with pytest.raises(AuthError) as ei:
        TokenVerifier(ring).verify(forged, now=now)
    assert ei.value.reason is DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE


class MutableKeySourceReloadFails:
    def __init__(self, keys, version):
        self._keys, self._version = keys, version

    def load(self):
        # 首次（构造时）正常；之后（受控重载）失败
        if not hasattr(self, "_primed"):
            self._primed = True
            return list(self._keys), self._version
        raise ConnectionError("key source down")


def test_expired_revoked_bad_signature_are_distinct(ring, now):
    issuer = TokenIssuer(ring)
    verifier = TokenVerifier(ring)
    expired = issuer.issue("e", ttl=dt.timedelta(minutes=1), now=now - dt.timedelta(minutes=2))
    live = issuer.issue("r", ttl=dt.timedelta(minutes=10), now=now)
    claims = verifier.verify(live, now=now)
    with pytest.raises(AuthError) as ei:
        verifier.verify(expired, now=now)
    assert ei.value.reason is DenyReason.TOKEN_EXPIRED
    with pytest.raises(AuthError) as ei:
        verifier.verify(live, revoked={claims.jti}, now=now)
    assert ei.value.reason is DenyReason.TOKEN_REVOKED
    with pytest.raises(AuthError) as ei:
        verifier.verify(live[:-3] + "AAA", now=now)
    assert ei.value.reason is DenyReason.TOKEN_SIGNATURE_MISMATCH
    with pytest.raises(AuthError) as ei:
        verifier.verify("not-a-token", now=now)
    assert ei.value.reason is DenyReason.TOKEN_MALFORMED
