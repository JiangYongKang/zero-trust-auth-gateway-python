"""发布批次穿过网关三段链路：同批一致、回退不影响在途、审计带发布标识。"""
from __future__ import annotations

import datetime as dt
import threading

import pytest

from ztauth.credentials import Credential, CredentialVersion, VersionState
from ztauth.errors import AuthError, DenyReason
from ztauth.gateway import Gateway
from ztauth.keys import SigningKey
from ztauth.policy import Policy, Rule
from ztauth.releases import ReleaseContent, ReleaseManager
from ztauth.sources import MutableReleaseSource
from ztauth.tokens import TokenIssuer

NOW = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)


def _key(kid: str, secret: bytes) -> SigningKey:
    return SigningKey(kid, secret, NOW - dt.timedelta(days=1),
                      NOW + dt.timedelta(days=30), "active")


def _policy(v: int, attr_value: str) -> Policy:
    return Policy(version=v, rules=(
        Rule(f"p{v}", "allow", "read", "db",
             require={"team": attr_value}, roles=("reader",)),
    ))


def _content(*, kid="k1", key_secret=b"key-v1", policy_v=1, team="payments",
             cred_secret=b"cred-v1", kv=1) -> ReleaseContent:
    return ReleaseContent(
        keys=(_key(kid, key_secret),),
        policy=_policy(policy_v, team),
        credentials={"db": Credential("db", ("reader",), (
            CredentialVersion(1, cred_secret, VersionState.CURRENT, None),
        ))},
        keys_version=kv,
    )


def _gateway(source: MutableReleaseSource, *, max_retained=8) -> tuple[Gateway, MutableReleaseSource]:
    mgr = ReleaseManager(source, max_retained=max_retained)
    return Gateway(released=mgr, clock=lambda: NOW), source


@pytest.fixture
def v1_source():
    return MutableReleaseSource(_content())


def _token(content: ReleaseContent, sub="alice", **kw):
    from ztauth.keys import KeyRing
    ring = KeyRing(_StaticKeys(list(content.keys), content.keys_version))
    return TokenIssuer(ring).issue(
        sub, ttl=dt.timedelta(minutes=10), roles=("reader",),
        attrs={"team": kw.get("team", "payments")}, now=NOW,
    )


class _StaticKeys:
    def __init__(self, keys, version):
        self._keys, self._version = keys, version

    def load(self):
        return list(self._keys), self._version


def test_authorize_uses_one_consistent_release(v1_source):
    gw, src = _gateway(v1_source)
    token = _token(src._content)  # noqa: SLF001
    result = gw.authorize("rq-1", token, "read", "db", now=NOW)
    assert result.release_id == 1
    assert result.decision.policy_version == 1
    assert result.credential is not None
    assert result.credential.secret == b"cred-v1"

    # 发布批次 2：密钥、策略要求的属性、凭据全部换新
    c2 = _content(kid="k2", key_secret=b"key-v2", policy_v=2,
                  team="billing", cred_secret=b"cred-v2", kv=2)
    rid = gw.publish(c2)
    assert rid == 2
    token2 = _token(c2, team="billing")
    r2 = gw.authorize("rq-2", token2, "read", "db", now=NOW)
    assert r2.release_id == 2
    assert r2.decision.policy_version == 2
    assert r2.credential.secret == b"cred-v2"

    # 旧批次令牌（旧 kid）在批次 2 中不可验签 -> unknown kid 回源（源即 c2，不含 k1）
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-old", token, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_UNKNOWN_KID
    assert ei.value.release_id == 2


def test_deny_result_also_reports_release_and_audits(v1_source, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="ztauth.audit")
    gw, src = _gateway(v1_source)
    # 策略要求 team=payments；令牌缺该属性 -> 缺属性拒绝
    token = _token_without_team(src._content)  # noqa: SLF001
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-deny", token, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.POLICY_MISSING_ATTRIBUTE
    assert ei.value.release_id == 1

    gw.publish(_content(kid="k2", key_secret=b"key-v2", policy_v=2,
                        team="billing", cred_secret=b"c2", kv=2))
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-deny2", token, "read", "db", now=NOW)
    assert ei.value.release_id == 2

    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert '"release_id": 1' in blob and '"release_id": 2' in blob
    assert "rq-deny" in blob
    assert "cred-v1" not in blob and token not in blob  # 机密不进日志


def _token_without_team(content: ReleaseContent) -> str:
    from ztauth.keys import KeyRing
    ring = KeyRing(_StaticKeys(list(content.keys), content.keys_version))
    return TokenIssuer(ring).issue(
        "bob", ttl=dt.timedelta(minutes=10), roles=("reader",),
        attrs={}, now=NOW,
    )


def test_rollback_restores_old_batch_for_new_requests(v1_source):
    gw, src = _gateway(v1_source)
    c1 = src._content  # noqa: SLF001
    c2 = _content(kid="k2", key_secret=b"key-v2", policy_v=2,
                  team="billing", cred_secret=b"cred-v2", kv=2)
    gw.publish(c2)
    assert gw.current_release_id() == 2
    assert gw.rollback(1) == 1

    r = gw.authorize("rq-back", _token(c1), "read", "db", now=NOW)
    assert r.release_id == 1
    assert r.credential.secret == b"cred-v1"
    # 批次 2 的令牌在回退后不再可用
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-x", _token(c2, team="billing"), "read", "db", now=NOW)
    assert ei.value.release_id == 1
    assert ei.value.reason is DenyReason.TOKEN_UNKNOWN_KID


def test_inflight_request_finishes_on_old_batch_during_rollback(v1_source):
    gw, src = _gateway(v1_source)
    entered, proceed = threading.Event(), threading.Event()
    c2 = _content(kid="k2", key_secret=b"key-v2", policy_v=2,
                  team="billing", cred_secret=b"cred-v2", kv=2)
    gw.publish(c2)
    token2 = _token(c2, team="billing")

    # 在凭据读取阶段阻塞，模拟请求进行到中段时发生回退
    import ztauth.gateway as gwmod
    orig = gwmod.read_credential

    def patched(store, name, **kw):
        real_load = store.load_all

        def blocked_load():
            entered.set()
            proceed.wait(2.0)
            return real_load()

        store.load_all = blocked_load  # type: ignore[method-assign]
        return orig(store, name, **kw)

    gwmod.read_credential = patched
    try:
        outcome: dict = {}

        def worker():
            r = gw.authorize("rq-slow", token2, "read", "db", now=NOW)
            outcome["release_id"] = r.release_id
            outcome["secret"] = r.credential.secret
            outcome["policy_version"] = r.decision.policy_version

        t = threading.Thread(target=worker)
        t.start()
        entered.wait(2.0)          # 请求已固定批次 2 并走到凭据阶段
        assert gw.current_release_id() == 2
        gw.rollback(1)             # 回退立即对后续请求生效
        assert gw.current_release_id() == 1
        proceed.set()              # 放行在途请求
        t.join()
    finally:
        gwmod.read_credential = orig

    # 在途请求按开始时看到的批次 2 完整结束，未被中途换版
    assert outcome == {
        "release_id": 2, "secret": b"cred-v2", "policy_version": 2,
    }
    # 后续请求使用批次 1
    r = gw.authorize("rq-after", _token(src._content), "read", "db", now=NOW)  # noqa: SLF001
    assert r.release_id == 1 and r.credential.secret == b"cred-v1"


def test_rollback_retired_vs_unknown_distinguishable_at_gateway(v1_source):
    from ztauth.releases import ReleaseError
    gw, _ = _gateway(v1_source, max_retained=2)
    gw.publish(_content(kid="k2", key_secret=b"b", policy_v=2, kv=2))
    gw.publish(_content(kid="k3", key_secret=b"c", policy_v=3, kv=3))
    # 批次 1 已超出保留期
    with pytest.raises(ReleaseError) as ei:
        gw.rollback(1)
    assert ei.value.kind == ReleaseError.RETIRED
    with pytest.raises(ReleaseError) as ei:
        gw.rollback(42)
    assert ei.value.kind == ReleaseError.NEVER_EXISTED


def test_unknown_kid_source_failure_maps_to_reload_unavailable(v1_source):
    class _FailingAfterInit:
        def __init__(self, first):
            self._first = first

        def load(self):
            if self._first is not None:
                out, self._first = self._first, None
                return out
            raise ConnectionError("source down")

    mgr = ReleaseManager(_FailingAfterInit(v1_source._content))  # noqa: SLF001
    gw = Gateway(released=mgr, clock=lambda: NOW)
    from ztauth.keys import KeyRing
    # 伪造 kid=k9 的令牌
    ring = KeyRing(_StaticKeys(list(v1_source._content.keys), 1))  # noqa: SLF001
    good = TokenIssuer(ring).issue("c", ttl=__import__("datetime").timedelta(minutes=1),
                                   kid="k1", now=NOW)
    import base64, json
    h, c, s = good.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    header["kid"] = "k9"
    h2 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":"),
                                             sort_keys=True).encode()).rstrip(b"=").decode()
    forged = f"{h2}.{c}.{s}"
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-down", forged, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE
    assert ei.value.release_id == 1
