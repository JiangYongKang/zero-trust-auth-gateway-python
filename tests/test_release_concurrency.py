"""发布批次在高并发与容量压力下的稳定性。

覆盖：
- 发布/回退与大量鉴权请求交错：每个请求只用单一批次，结论可复现；
- 同一发布批次的并发加载对上游源只读一次（single-flight）；
- 未知 kid 洪水下，上游读取次数按"代际"有界；
- 回退中在途请求按开始时批次完整结束。
"""
from __future__ import annotations

import datetime as dt
import threading
import time
from collections import Counter

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
from ztauth.releases import (
    InMemoryReleaseSource,
    ReleaseManager,
    ReleasePayload,
)
from ztauth.sources import MutableKeySource
from ztauth.tokens import TokenIssuer

NOW = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)


def _key(kid: str, secret: bytes, state: str = "active") -> SigningKey:
    return SigningKey(
        kid, secret,
        NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30), state,
    )


def _policy(v: int) -> Policy:
    return Policy(
        v,
        (Rule(f"r{v}", "allow", "read", "db",
              require={"v": str(v)}, roles=("reader",)),),
    )


def _cred(secret: bytes, version: int = 1) -> dict[str, Credential]:
    return {
        "db": Credential(
            "db", ("reader",),
            (CredentialVersion(version, secret, VersionState.CURRENT, None),),
        ),
    }


def _forged_token(kid: str) -> str:
    """语法合法（三段 base64url、头含 alg/typ/kid）但 kid 不存在的令牌。"""
    import base64
    import json

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps(
        {"alg": "HS256", "typ": "ZT1", "kid": kid},
        separators=(",", ":"), sort_keys=True,
    ).encode())
    claims = b64(json.dumps({"sub": "x", "jti": "j"}).encode())
    return f"{header}.{claims}.sig"


def _build_gateway(retain: int = 10):
    keys1 = [_key("k1", b"one")]
    ring = KeyRing(MutableKeySource(keys1, version=1))
    vault = InMemoryCredentialVault(_cred(b"s1"))
    store = PolicyStore(type(
        "Static", (), {"load": lambda self: _policy(1)},
    )())
    p1 = ReleasePayload(1, tuple(keys1), 1, _policy(1), vault.load_all())
    src = InMemoryReleaseSource(p1)
    mgr = ReleaseManager(src, retain=retain)
    gw = Gateway(ring, store, vault, AuditLogger(),
                 releases=mgr, clock=lambda: NOW)
    return gw, mgr, src, vault


def _token_for(rid: int, secret: bytes, v: int) -> str:
    ring = type(
        "R", (),
        {
            "lookup": lambda self, kid, now=None: type(
                "L", (), {"kind": "found", "key": _key(kid, secret)}
            )(),
            "current_signing_key": lambda self, now=None: _key(f"k{rid}", secret),
        },
    )()
    return TokenIssuer(ring).issue(
        f"u{rid}", ttl=dt.timedelta(minutes=10),
        roles=("reader",), attrs={"v": str(v)}, now=NOW,
    )


def test_concurrent_publish_rollback_interleaved_with_authz():
    gw, mgr, src, vault = _build_gateway(retain=50)
    # 预发布 1..20；每批次密钥 kid=k{id}、策略要求 attrs.v==id、凭据 s{id}
    tokens: dict[int, str] = {1: _token_for(1, b"one", 1)}
    secrets_map = {1: b"s1"}
    for rid in range(2, 21):
        sec = f"s{rid}".encode()
        ksec = f"key{rid}".encode()
        gw.publish_batch(
            keys=(_key(f"k{rid}", ksec),),
            key_version=rid, policy=_policy(rid),
            credentials=_cred(sec, version=rid),
        )
        secrets_map[rid] = sec
        tokens[rid] = _token_for(rid, ksec, rid)

    outcomes: Counter[tuple] = Counter()
    outcomes_lock = threading.Lock()
    errors: list[Exception] = []
    errors_lock = threading.Lock()
    barrier = threading.Barrier(17)  # 16 鉴权线程 + 1 切换线程
    def auth_worker(tid):
        barrier.wait()
        for i in range(1, 401):
            rid = mgr.current_id
            try:
                res = gw.authorize(
                    f"c-{tid}-{i}", tokens[rid], "read", "db", now=NOW,
                )
                used = res.release_id
                # 关键不变量：放行结论、凭据（内容与版本）、策略版本、发布标识
                # 全部同批对齐，绝不能出现跨批混用
                assert res.credential.secret == secrets_map[used]
                assert res.credential.version == used
                assert res.decision.policy_version == used
                got = (used, "allow")
            except AuthError as exc:
                got = (rid, exc.reason.value)
            except Exception as exc:  # 其他异常（含断言）必须让测试失败可见
                with errors_lock:
                    errors.append(exc)
                return
            with outcomes_lock:
                outcomes[got] += 1
            time.sleep(0.0005)  # 让出执行权，确保与切换操作真实交错

    def switcher():
        barrier.wait()
        try:
            for rid in [1, 20, 5, 20, 10, 20, 1, 20]:
                gw.rollback_batch(rid)
                time.sleep(0.01)  # 每个批次停留一段时间，让鉴权请求落到该批
        except Exception as exc:
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=auth_worker, args=(t,)) for t in range(16)]
    sw = threading.Thread(target=switcher)
    for t in threads + [sw]:
        t.start()
    for t in threads + [sw]:
        t.join()

    total = sum(outcomes.values())
    assert not errors, errors
    assert total > 0
    # 允许可能出现 policy_deny（令牌批次与当前批次错位的瞬间），但只允许该原因，
    # 且绝不能出现凭据/密钥类错误（那意味着跨批次混用）
    seen_reasons = {reason for _, reason in outcomes}
    assert seen_reasons <= {"allow", DenyReason.POLICY_DENY.value}
    # 至少覆盖到多个批次
    assert len({rid for rid, _ in outcomes}) > 1


def test_concurrent_load_of_same_release_reads_source_once(monkeypatch):
    """32 个线程同时 refresh（上游只有同一个新批次）：源只被读一次。"""
    gw, mgr, src, vault = _build_gateway()
    src.publish((_key("k2", b"two"),), 2, _policy(2), _cred(b"s2"))

    n = 32
    may_load = threading.Event()
    load_started = threading.Event()
    load_calls = {"n": 0}
    call_lock = threading.Lock()

    def slow_load():
        with call_lock:
            load_calls["n"] += 1
            if load_calls["n"] == 1:
                load_started.set()
        may_load.wait()  # 唯一加载者在此阻塞，等待其余线程排队
        return src.load_latest()

    monkeypatch.setattr(mgr, "_source", type(
        "S", (), {"load_latest": lambda self: slow_load()},
    )())

    all_ready = threading.Barrier(n)
    waiters = {"n": 0}
    waiters_full = threading.Event()

    # 给等待路径插桩：统计锁外等待复用的线程数
    orig_wait = threading.Event.wait

    def counted_wait(self, timeout=None):  # noqa: ANN001
        if self is getattr(mgr, "_inflight", None):
            with call_lock:
                waiters["n"] += 1
                if waiters["n"] == n - 1:
                    waiters_full.set()
        return orig_wait(self, timeout)

    monkeypatch.setattr(threading.Event, "wait", counted_wait)

    def worker():
        all_ready.wait()
        mgr.refresh()

    ts = [threading.Thread(target=worker) for _ in range(n)]
    for t in ts:
        t.start()
    load_started.wait()     # 唯一加载者已进入源读取并阻塞
    waiters_full.wait()     # 其余 31 个线程都已在 inflight 上等待
    may_load.set()
    for t in ts:
        t.join()
    assert mgr.current_id == 2
    assert load_calls["n"] == 1  # 真正重叠的 32 次 refresh 合并为一次源读取
    assert waiters["n"] == n - 1


def test_unknown_kid_flood_reads_source_bounded_by_generation():
    """大量持续的未知 kid 请求：每个上游代际至多触发一次源读取。"""
    gw, mgr, src, vault = _build_gateway()

    def unknown_request(tid, i):
        # 语法合法、但 kid 在当前批次不存在（每个请求 kid 都不同）
        token = _forged_token(f"unknown-{tid}-{i}")
        try:
            gw.authorize(f"u-{tid}-{i}", token, "read", "db", now=NOW)
        except AuthError as exc:
            return exc.reason
        return None

    barrier = threading.Barrier(24)
    errors: list[DenyReason] = []
    errors_lock = threading.Lock()

    def worker(tid):
        barrier.wait()
        for i in range(50):
            with errors_lock:
                reason = unknown_request(tid, i)
                if reason is not None:
                    errors.append(reason)

    ts = [threading.Thread(target=worker, args=(t,)) for t in range(24)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # 1200 次互不相同的未知 kid 洪水：除构造期外只读源 1 次（代际门闩）
    assert src.load_count == 2
    assert set(errors) == {DenyReason.TOKEN_UNKNOWN_KID}

    # 上游发布新一代后，门闩复位：再允许恰好一次读取
    src.publish((_key("k2", b"two"),), 2, _policy(2), _cred(b"s2"))
    gw.publish_batch(keys=(_key("k2", b"two"),), key_version=2,
                     policy=_policy(2), credentials=_cred(b"s2"))
    for i in range(200):
        unknown_request(9, i)
    assert src.load_count == 3


def test_inflight_request_completes_on_started_batch_during_rollback():
    gw, mgr, src, vault = _build_gateway(retain=5)
    ksec2 = b"key-two"
    gw.publish_batch(keys=(_key("k2", ksec2),), key_version=2,
                     policy=_policy(2), credentials=_cred(b"s2"))
    token2 = _token_for(2, ksec2, 2)

    entered = threading.Event()
    hold = threading.Event()
    results: list[tuple[int, bytes]] = []

    def slow_request():
        # 手工 pin：进入批次 2 后阻塞，等回退到 1 再结束
        with mgr.use_current() as bundle:
            entered.set()
            hold.wait()
            # 即便当前指针已回退到 1，仍能用 pin 住的批次 2 判完
            from ztauth.tokens import TokenVerifier
            claims = TokenVerifier(bundle.ring).verify(token2, now=NOW)
            results.append((bundle.release_id, claims.sub.encode()))

    t = threading.Thread(target=slow_request)
    t.start()
    entered.wait()
    gw.rollback_batch(1)
    assert mgr.current_id == 1
    hold.set()
    t.join()
    assert results == [(2, b"u2")]
    # 批次 2 仍在保留窗口
    assert 2 in mgr.retained_ids()
