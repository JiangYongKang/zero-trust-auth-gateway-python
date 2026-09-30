"""发布批次与原有单项轮换 / 热更新路径的兼容性。

- 不传 releases 时，Gateway 行为与历史完全一致（单项路径）；
- 启用发布批次后，单项 rotate/reload 可先把组件改到目标态，再由
  publish_batch 打包成同批原子生效；
- 发布模式下 allow/deny 的结论仍可复现，且都带 release_id；
- 发布/回退是指针切换，不存在配置短暂为空导致误拒。
"""
from __future__ import annotations

import datetime as dt

import pytest

from ztauth.audit import AuditLogger
from ztauth.credentials import (
    Credential,
    CredentialVersion,
    InMemoryCredentialVault,
    VersionState,
)
from ztauth.errors import AuthError, DenyReason
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import Policy, PolicyStore, Rule
from ztauth.releases import InMemoryReleaseSource, ReleaseManager, ReleasePayload
from ztauth.sources import MutableKeySource
from ztauth.tokens import TokenIssuer

NOW = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)


def _key(kid, secret, state="active"):
    return SigningKey(kid, secret,
                      NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30), state)


class _StaticPolicySource:
    def __init__(self, policy):
        self.policy = policy

    def load(self):
        return self.policy


def _build(enabled: bool):
    keys = [_key("k1", b"one")]
    ring = KeyRing(MutableKeySource(keys, version=1))
    policy = Policy(1, (Rule("r1", "allow", "read", "db",
                             require={"v": "1"}, roles=("reader",)),))
    store = PolicyStore(_StaticPolicySource(policy))
    vault = InMemoryCredentialVault({
        "db": Credential("db", ("reader",),
                         (CredentialVersion(1, b"s1", VersionState.CURRENT, None),)),
    })
    releases = None
    if enabled:
        initial = ReleasePayload(1, tuple(keys), 1, policy, vault.load_all())
        releases = ReleaseManager(InMemoryReleaseSource(initial), retain=5)
    gw = Gateway(ring, store, vault, AuditLogger(),
                 releases=releases, clock=lambda: NOW)
    return gw, ring, store, vault, (releases if enabled else None)


def _token(ring, v):
    return TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"v": str(v)}, now=NOW,
    )


def test_legacy_path_unchanged_without_releases():
    gw, ring, store, vault, mgr = _build(enabled=False)
    assert mgr is None
    assert gw.current_release_id() is None
    res = gw.authorize("leg-1", _token(ring, 1), "read", "db", now=NOW)
    assert res.release_id is None
    assert res.credential.secret == b"s1"
    # 单项策略热更新仍走原路径
    store._policy = Policy(2, (Rule("r2", "allow", "read", "db",
                                    require={"v": "2"}, roles=("reader",)),))
    gw.reload_policies()
    with pytest.raises(AuthError) as ei:
        gw.authorize("leg-2", _token(ring, 1), "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.POLICY_DENY


def test_individual_rotation_can_be_bundled_into_one_release():
    gw, ring, store, vault, mgr = _build(enabled=True)
    tok1 = _token(ring, 1)
    # 批次 1 正常
    r1 = gw.authorize("b-1", tok1, "read", "db", now=NOW)
    assert r1.release_id == 1 and r1.credential.version == 1

    # 分别用单项能力改各组件：密钥轮换、策略改版本、凭据轮换
    new_keys = [_key("k1", b"one", "retiring"), _key("k2", b"two")]
    ring._source.set_keys(new_keys, version=2)
    assert ring.reload() == 2
    store._policy = Policy(2, (Rule("r2", "allow", "read", "db",
                                    require={"v": "2"}, roles=("reader",)),))
    gw.reload_policies()
    v2 = vault.rotate("db", b"s2", now=NOW)
    assert v2 == 2

    # 在打包发布前，当前批次仍为 1：单项改动不影响发布视图（整批一致）
    assert mgr.current_id == 1
    still = gw.authorize("b-1b", tok1, "read", "db", now=NOW)
    assert still.release_id == 1 and still.credential.secret == b"s1"

    # 打包成一个新批次（省略参数=取各组件当前快照）
    rid = gw.publish_batch()
    assert rid == 2
    tok2 = TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"v": "2"}, now=NOW,
    )
    r2 = gw.authorize("b-2", tok2, "read", "db", now=NOW)
    assert r2.release_id == 2
    assert r2.credential.version == 2 and r2.credential.secret == b"s2"
    # 新批次策略要求 v=2，旧令牌（attrs v=1）按新策略默认拒绝
    with pytest.raises(AuthError) as ei:
        gw.authorize("b-2d", tok1, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.POLICY_DENY


def test_deny_results_also_carry_release_id(caplog):
    gw, ring, store, vault, mgr = _build(enabled=True)
    # 无匹配规则的 action -> policy_deny，结果以异常给出；审计带 release_id
    tok = _token(ring, 1)
    with pytest.raises(AuthError) as ei:
        gw.authorize("d-1", tok, "write", "db", now=NOW)
    assert ei.value.reason is DenyReason.POLICY_DENY
    records = [r.message for r in caplog.records]
    assert any('"release_id": 1' in m and '"request_id": "d-1"' in m
               for m in records)


def test_publish_switch_never_serves_empty_config(caplog):
    """快速连续发布期间，所有请求都必须落到某个完整批次，不出现误拒为空。"""
    gw, ring, store, vault, mgr = _build(enabled=True)
    import threading
    stop = threading.Event()
    bad: list[str] = []

    def publisher():
        for rid in range(2, 12):
            gw.publish_batch(
                keys=(_key(f"k{rid}", f"key{rid}".encode()),),
                key_version=rid,
                policy=Policy(rid, (Rule(f"r{rid}", "allow", "read", "db",
                                         require={"v": str(rid)},
                                         roles=("reader",)),)),
                credentials={
                    "db": Credential(
                        "db", ("reader",),
                        (CredentialVersion(rid, f"s{rid}".encode(),
                                           VersionState.CURRENT, None),),
                    ),
                },
            )
        stop.set()

    def caller(tid):
        i = 0
        while not stop.is_set():
            i += 1
            rid = mgr.current_id
            ring_now = mgr.current().ring
            tok = TokenIssuer(ring_now).issue(
                "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
                attrs={"v": str(rid)}, now=NOW,
            )
            res = gw.authorize(f"f-{tid}-{i}", tok, "read", "db", now=NOW)
            if res.credential is None:
                bad.append("empty")

    pt = threading.Thread(target=publisher)
    callers = [threading.Thread(target=caller, args=(t,)) for t in range(8)]
    pt.start()
    for c in callers:
        c.start()
    pt.join()
    for c in callers:
        c.join()
    assert not bad


def test_unknown_kid_picks_up_new_release_then_whole_request_uses_it():
    """上游发布了含新 kid 的批次；首个未知 kid 请求触发一次受控刷新，
    然后整请求用新批次完整判完（密钥/策略/凭据同批）。"""
    gw, ring, store, vault, mgr = _build(enabled=True)

    # 上游直接出现批次 2（不经过本地 publish_batch），含 k2 与对应策略/凭据
    new_payload = __import__("ztauth.releases", fromlist=["ReleasePayload"]).ReleasePayload(
        2,
        (_key("k2", b"two"),), 2,
        Policy(2, (Rule("r2", "allow", "read", "db",
                        require={"v": "2"}, roles=("reader",)),)),
        {"db": Credential("db", ("reader",),
                          (CredentialVersion(2, b"s2", VersionState.CURRENT, None),))},
    )
    # 通过 InMemoryReleaseSource 写入"上游最新批次"（尚未被管理器采纳）
    gw._releases._source._latest = new_payload  # noqa: SLF001

    from ztauth.keys import FrozenKeyRing
    tok2 = TokenIssuer(FrozenKeyRing([_key("k2", b"two")], 2)).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"v": "2"}, now=NOW,
    )
    res = gw.authorize("nk-1", tok2, "read", "db", now=NOW)
    assert res.release_id == 2
    assert res.credential.secret == b"s2"
    assert res.decision.policy_version == 2


def test_release_source_down_is_distinct_reason(monkeypatch):
    gw, ring, store, vault, mgr = _build(enabled=True)

    def boom():
        raise ConnectionError("release source down")

    monkeypatch.setattr(mgr, "_load_single_flight", lambda **kw: boom())
    # 复位门闩使其触发一次受控刷新
    mgr._unknown_checked_generation = None

    import base64
    import json

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps(
        {"alg": "HS256", "typ": "ZT1", "kid": "k-ghost"},
        separators=(",", ":"), sort_keys=True).encode())
    forged = f"{header}.{b64(b'{}')}.sig"
    with pytest.raises(AuthError) as ei:
        gw.authorize("nk-down", forged, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE
