"""令牌校验拒绝原因可区分性测试。"""

from __future__ import annotations

import base64
import json

import pytest

from ztauth.errors import TokenError, TokenReasons
from ztauth.keyring import Keyring, StaticKeySource, generate_key
from ztauth.tokens import SetRevocationList, issue_token, verify_token


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture()
def env(monkeypatch):
    t = {"now": 950.0}
    clock = lambda: t["now"]
    old = generate_key("old", not_before=0.0, not_after=1000.0)
    new = generate_key("new", not_before=1000.0, not_after=2000.0)
    src = StaticKeySource([old])
    kr = Keyring(src, overlap_seconds=60.0, clock=clock)
    return t, clock, old, new, src, kr


def test_issue_and_verify_happy_path(env) -> None:
    t, clock, old, new, src, kr = env
    tok, claims = issue_token(
        kr, sub="alice", ttl_seconds=50, scopes={"read", "db"},
        attributes={"dept": "eng"}, clock=clock,
    )
    assert claims.kid == "old"
    out = verify_token(tok, kr, clock=clock)
    assert out.sub == "alice"
    assert out.scopes == frozenset({"read", "db"})
    assert out.attributes == {"dept": "eng"}


def test_token_issued_before_rotation_verifies_in_overlap(env) -> None:
    t, clock, old, new, src, kr = env
    tok, claims = issue_token(kr, sub="alice", ttl_seconds=100, clock=clock)
    assert claims.kid == "old"
    # 轮换发布：来源同时提供旧/新密钥并通知密钥环重载，时间进入重叠窗口
    src.set_keys([old, new])
    kr.reload()
    t["now"] = 1020.0
    kr._clock = clock  # 密钥环时钟随测试时间推进到重叠期
    out = verify_token(tok, kr, clock=clock)  # 旧令牌仍可验
    assert out.sub == "alice"
    # 新签发一律走严格 active 的新密钥
    _, new_claims = issue_token(kr, sub="bob", ttl_seconds=10, clock=clock)
    assert new_claims.kid == "new"


def test_reason_malformed(env) -> None:
    _, clock, *_ = env
    kr = env[5]
    for bad in ["", "nodot", ".", "a.b", 12345]:  # type: ignore[list-item]
        with pytest.raises(TokenError) as ei:
            verify_token(bad, kr, clock=clock)  # type: ignore[arg-type]
        assert ei.value.reason == TokenReasons.MALFORMED


def test_reason_signature_mismatch(env) -> None:
    t, clock, *_ = env
    kr = env[5]
    tok, _ = issue_token(kr, sub="alice", ttl_seconds=50, clock=clock)
    head, mac = tok.split(".")
    tampered = head + "." + ("A" * len(mac))
    with pytest.raises(TokenError) as ei:
        verify_token(tampered, kr, clock=clock)
    assert ei.value.reason == TokenReasons.SIGNATURE_MISMATCH


def test_reason_expired_and_not_yet_valid(env) -> None:
    t, clock, *_ = env
    kr = env[5]
    tok, _ = issue_token(kr, sub="alice", ttl_seconds=50, clock=clock)
    with pytest.raises(TokenError) as ei:
        verify_token(tok, kr, clock=lambda: 1000.0)
    assert ei.value.reason == TokenReasons.EXPIRED

    future, _ = issue_token(
        kr, sub="alice", ttl_seconds=50, clock=clock, not_before=1500.0
    )
    with pytest.raises(TokenError) as ei:
        verify_token(future, kr, clock=clock)
    assert ei.value.reason == TokenReasons.NOT_YET_VALID


def test_reason_revoked(env) -> None:
    t, clock, *_ = env
    kr = env[5]
    tok, claims = issue_token(kr, sub="alice", ttl_seconds=50, clock=clock)
    rev = SetRevocationList({claims.jti})
    with pytest.raises(TokenError) as ei:
        verify_token(tok, kr, revocation=rev, clock=clock)
    assert ei.value.reason == TokenReasons.REVOKED


def test_reason_unknown_kid_after_controlled_reload(env) -> None:
    t, clock, old, new, src, kr = env
    tok, claims = issue_token(kr, sub="alice", ttl_seconds=50, clock=clock)
    # 篡改 kid 为来源中不存在的标识：触发重载后仍未知
    payload = json.loads(
        base64.urlsafe_b64decode(tok.split(".")[0] + "==")
    )
    payload["kid"] = "ghost"
    head = _b64u(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    ghost = head + "." + tok.split(".")[1]
    with pytest.raises(TokenError) as ei:
        verify_token(ghost, kr, clock=clock)
    assert ei.value.reason == TokenReasons.UNKNOWN_KID

    # 若重载后该 kid 上线（旧密钥到期但来源补齐旧密钥用于重叠验签），
    # 未知 kid 场景同样由密钥环测试覆盖受控恢复路径。
