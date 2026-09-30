"""持续发布/回退与并发鉴权交错：不跨批、无空窗误拒、结论可复现。"""
from __future__ import annotations

import datetime as dt
import threading

from ztauth.errors import AuthError, DenyReason
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.releases import ReleaseContent, ReleaseManager
from ztauth.sources import MutableReleaseSource
from ztauth.tokens import TokenIssuer

NOW = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)


def _content(v: int) -> ReleaseContent:
    from ztauth.credentials import Credential, CredentialVersion, VersionState
    from ztauth.policy import Policy, Rule
    key = SigningKey(f"k{v}", f"key-{v}".encode(),
                     NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30),
                     "active")
    return ReleaseContent(
        keys=(key,),
        policy=Policy(version=v, rules=(
            Rule(f"p{v}", "allow", "read", "db",
                 require={"v": str(v)}, roles=("reader",)),
        )),
        credentials={"db": Credential("db", ("reader",), (
            CredentialVersion(v, f"cred-{v}".encode(),
                              VersionState.CURRENT, None),
        ))},
        keys_version=v,
    )


def _token_for(v: int) -> str:
    ring = KeyRing(_Source(list(_content(v).keys), v))
    return TokenIssuer(ring).issue(
        f"u{v}", ttl=dt.timedelta(minutes=10), roles=("reader",),
        attrs={"v": str(v)}, now=NOW,
    )


class _Source:
    def __init__(self, keys, version):
        self._keys, self._version = keys, version

    def load(self):
        return list(self._keys), self._version


def test_publish_rollback_interleaved_with_authz():
    # 保留全部批次（容量 64），回退始终可用
    N = 20
    src = MutableReleaseSource(_content(1))
    mgr = ReleaseManager(src, max_retained=N + 2)
    gw = Gateway(released=mgr, clock=lambda: NOW)
    for v in range(2, N + 1):
        gw.publish(_content(v))
    tokens = {v: _token_for(v) for v in range(1, N + 1)}

    results: list[tuple[int, int, int, str]] = []  # rid, policy_v, cred_v, key_v
    results_lock = threading.Lock()
    stop = threading.Event()
    errors: list[AuthError] = []

    def auth_worker(tid: int):
        i = 0
        while not stop.is_set():
            i += 1
            # 每个请求带的令牌 kid 随 i 轮换；只有 kid 与当前批次一致时才成功，
            # 否则应稳定地得到 token_unknown_kid（且带 release_id），不能出现
            # 空配置/内部错误，更不能出现跨批放行。
            v = (tid * 7 + i) % N + 1
            rid = gw.current_release_id()
            try:
                r = gw.authorize(f"c-{tid}-{i}", tokens[v], "read", "db", now=NOW)
                with results_lock:
                    results.append((
                        r.release_id,
                        r.decision.policy_version,
                        r.credential.version,
                        int(r.credential.secret.decode().split("-")[1]),
                    ))
            except AuthError as exc:
                # 唯一允许的失败：kid 与当前批次不一致；其 release_id 必须等于
                # 请求开始时读到的当前标识
                assert exc.reason is DenyReason.TOKEN_UNKNOWN_KID
                assert exc.release_id == rid
                errors.append(exc)

    def writer():
        # 来回发布/回退：新请求看到的当前标识不断变化
        for v in list(range(N, 0, -1)) + list(range(1, N + 1)):
            gw.rollback(v)

    callers = [threading.Thread(target=auth_worker, args=(t,)) for t in range(8)]
    w = threading.Thread(target=writer)
    for c in callers:
        c.start()
    w.start()
    w.join()
    stop.set()
    for c in callers:
        c.join()

    assert results, "必须实际产生过成功判定"
    # 核心不变量：成功请求的发布标识、策略版本、凭据版本、密钥 kid 全部同批
    for rid, pv, cv, kv in results:
        assert rid == pv == cv == kv, (rid, pv, cv, kv)


def test_never_empty_window_under_burst_publish():
    # 极小保留容量 + 高频发布：读侧在任何时刻都能拿到完整批次
    src = MutableReleaseSource(_content(1))
    mgr = ReleaseManager(src, max_retained=1)
    gw = Gateway(released=mgr, clock=lambda: NOW)

    stop = threading.Event()
    bad: list[str] = []

    def reader():
        token = _token_for(1)
        while not stop.is_set():
            try:
                with mgr.acquire() as rel:
                    # 批次必须自洽：有密钥、有策略、有凭据
                    assert rel.content.keys and rel.content.policy.rules
                    assert rel.content.credentials.get("db")
            except Exception as exc:  # pragma: no cover
                bad.append(repr(exc))

    def publisher():
        for v in range(2, 200):
            gw.publish(_content(v if v % 2 else 1))  # 交替内容，容量 1 强淘汰

    r = threading.Thread(target=reader)
    p = threading.Thread(target=publisher)
    r.start()
    p.start()
    p.join()
    stop.set()
    r.join()
    assert not bad


def test_concurrent_load_of_same_batch_reads_source_once():
    # 同一批次的未知 kid 并发回源：只允许真正读取一次
    src = MutableReleaseSource(_content(1))
    mgr = ReleaseManager(src)
    rel = mgr.current()
    barrier = threading.Barrier(24)

    def worker():
        barrier.wait()
        mgr.reload_for_unknown_kid(rel, "missing-kid")

    ts = [threading.Thread(target=worker) for _ in range(24)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # 构造期 1 次 + 合并回源 1 次
    assert src.load_count == 2
