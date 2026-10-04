"""未知 kid 冲击下上游真实读取次数的确定上限（回归压测发现的问题）。

覆盖业务场景：
- 未知标识种类远超单批/负缓存规模（几十 -> 上千），读取次数不随种类数上涨；
- 同一批未知标识反复轮换，第二轮、第三轮不再回源；
- 大量并发请求携带同一个未知标识：最多真实读取一次；
- 大量并发请求携带互不相同的未知标识：读取次数不放大到并发量级；
- 节流不耽误合法密钥更新：新 kid 最迟一个间隔后被发现并生效；
- 上游失败：并发等待方拿到同一个明确异常、不被挂住，读取仍有上限。

上限语义（release 批次模式）：
    真实 load 次数 <= 构造期 1 次 + 1 + floor(经过时间 / reload_min_interval)
与未知标识种类数、请求总量、负缓存容量均无关。
"""
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

from conftest import FakeClock

NOW = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)
INTERVAL = 5.0  # 回源节流间隔（秒），测试用假时钟精确控制


def _key(kid: str, secret: bytes = b"k-secret") -> SigningKey:
    return SigningKey(kid, secret, NOW - dt.timedelta(days=1),
                      NOW + dt.timedelta(days=30), "active")


def _content(kid: str = "k1", kv: int = 1) -> ReleaseContent:
    return ReleaseContent(
        keys=(_key(kid),),
        policy=Policy(version=kv, rules=(
            Rule(f"r{kv}", "allow", "read", "db",
                 require={}, roles=("reader",)),
        )),
        credentials={"db": Credential("db", ("reader",), (
            CredentialVersion(1, b"cred", VersionState.CURRENT, None),
        ))},
        keys_version=kv,
    )


def _manager(src, *, capacity=16, clock=None):
    return ReleaseManager(src, negative_cache_size=capacity,
                          reload_min_interval=INTERVAL,
                          clock=clock or FakeClock())


# --------------------------------------------------------------------- #
# 场景 1：未知标识种类远超单批/负缓存规模，读取次数收敛到确定上限
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("n_kids", [50, 200, 1000])
def test_distinct_unknown_kids_far_beyond_capacity_reads_bounded(n_kids):
    src = MutableReleaseSource(_content())
    clock = FakeClock()
    mgr = _manager(src, capacity=16, clock=clock)  # 容量 16 << 种类数

    rel = mgr.current()
    for n in range(n_kids):
        mgr.reload_for_unknown_kid(rel, f"ghost-{n}")

    # 构造期 1 次 + 节流窗口内恰好 1 次：与种类数（50/200/1000）无关
    assert src.load_count == 2

    # 时间推进 k 个间隔：每个间隔最多放行 1 次真实读取
    rounds = 4
    for r in range(rounds):
        clock.advance(INTERVAL)
        for n in range(n_kids):
            mgr.reload_for_unknown_kid(rel, f"ghost-{n}")
        assert src.load_count == 2 + (r + 1)
    # 总上限：2 + 经过的间隔数，而不是 2 + 间隔数 * 种类数
    assert src.load_count == 2 + rounds


# --------------------------------------------------------------------- #
# 场景 2：同一批未知标识反复轮换，第二轮、第三轮不再回源
# --------------------------------------------------------------------- #
def test_rotating_same_batch_of_unknown_kids_no_reload_in_later_rounds():
    src = MutableReleaseSource(_content())
    clock = FakeClock()
    # 负缓存容量故意小于轮换批大小：上限由节流保证，而非缓存够大
    mgr = _manager(src, capacity=8, clock=clock)
    kids = [f"rot-{n}" for n in range(64)]

    rel = mgr.current()
    for kid in kids:  # 第一轮
        mgr.reload_for_unknown_kid(rel, kid)
    assert src.load_count == 2

    for _ in range(3):  # 第二、三、四轮：同一批标识反复轮换
        for kid in kids:
            mgr.reload_for_unknown_kid(rel, kid)
        assert src.load_count == 2  # 不再回源


# --------------------------------------------------------------------- #
# 场景 3：大量并发请求携带同一个未知标识，最多真实读取一次
# --------------------------------------------------------------------- #
def test_concurrent_same_unknown_kid_reads_source_at_most_once():
    src = MutableReleaseSource(_content())
    mgr = _manager(src)
    rel = mgr.current()
    barrier = threading.Barrier(32)
    errors: list[BaseException] = []

    def worker():
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(rel, "ghost")
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker) for _ in range(32)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    assert src.load_count == 2  # 构造期 1 次 + 合并后恰好 1 次


# --------------------------------------------------------------------- #
# 场景 4：大量并发请求携带互不相同的未知标识，读取次数不随并发放大
# --------------------------------------------------------------------- #
def test_concurrent_distinct_unknown_kids_reads_not_proportional_to_concurrency():
    src = MutableReleaseSource(_content())
    mgr = _manager(src)
    n_threads = 64
    barrier = threading.Barrier(n_threads)
    errors: list[BaseException] = []

    def worker(n):
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(mgr.current(), f"ghost-{n}")
        except BaseException as exc:  #  pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(n,)) for n in range(n_threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    # 64 个并发、64 种标识：真实读取只有构造期 1 次 + 合并/节流后 1 次
    assert src.load_count == 2


# --------------------------------------------------------------------- #
# 场景 5：节流不耽误合法密钥更新——新 kid 最迟一个间隔后被发现
# --------------------------------------------------------------------- #
def test_legit_new_key_discovered_within_one_interval():
    src = MutableReleaseSource(_content("k1", kv=1))
    clock = FakeClock()
    mgr = _manager(src, clock=clock)

    # k2 尚未发布：第一次回源确认不含，进入负缓存
    mgr.reload_for_unknown_kid(mgr.current(), "k2")
    assert src.load_count == 2
    assert mgr.current_id() == 1

    # 上游随后发布 k2；节流窗口内的请求仍按旧结论（unknown），不回源
    src.set_content(_content("k2", kv=2))
    mgr.reload_for_unknown_kid(mgr.current(), "k2")
    assert src.load_count == 2
    assert mgr.current_id() == 1

    # 一个间隔过后：真实回源发现 k2，原子发布为新批次，对后续请求生效
    clock.advance(INTERVAL)
    mgr.reload_for_unknown_kid(mgr.current(), "k2")
    assert src.load_count == 3
    assert mgr.current_id() == 2
    assert any(k.kid == "k2" for k in mgr.current().content.keys)


# --------------------------------------------------------------------- #
# 场景 6：上游失败——并发等待方拿到同一明确异常、不挂住、读取仍有上限
# --------------------------------------------------------------------- #
class _FlakySource:
    def __init__(self, content: ReleaseContent) -> None:
        self._content = content
        self.load_count = 0
        self.down = False
        self.gate: threading.Event | None = None  # 设置后 load 阻塞至门闩放开

    def load(self) -> ReleaseContent:
        self.load_count += 1
        if self.gate is not None:
            self.gate.wait(5.0)
        if self.down:
            raise ConnectionError("key source down")
        return self._content


def test_upstream_failure_concurrent_waiters_get_same_clear_error():
    src = _FlakySource(_content())
    clock = FakeClock()
    mgr = _manager(src, clock=clock)
    src.down = True  # 构造期读取成功后才宕机
    src.gate = threading.Event()  # 让首次失败回源阻塞，制造确定的并发等待窗口

    n_threads = 16
    barrier = threading.Barrier(n_threads)
    errors: list[BaseException] = []

    def worker(n):
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(mgr.current(), f"ghost-{n % 4}")
        except BaseException as exc:
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(n,)) for n in range(n_threads)]
    for t in ts:
        t.start()
    # 等全部线程进入等待（leader 阻塞在 load 内，其余挂在 inflight 上）
    deadline = NOW  # 占位，避免误用；实际用简单轮询
    del deadline
    import time as _time
    for _ in range(100):
        if src.load_count == 1 + 1:
            break
        _time.sleep(0.01)
    _time.sleep(0.2)  # 给其余线程足够时间挂上 inflight
    src.gate.set()    # 放行：leader 抛 ConnectionError
    for t in ts:
        t.join(timeout=10.0)  # 不被挂住：等待方必须在有限时间内返回
        assert not t.is_alive()

    # 所有等待方拿到明确、可解释的同一个失败（而非 unknown 之类的静默结论）
    assert len(errors) == n_threads
    assert all(isinstance(e, ConnectionError) for e in errors)
    # 失败也占住节流窗口：16 个并发只放大为 1 次真实读取
    assert src.load_count == 1 + 1

    # 窗口内再次冲击：不重复回源；窗口过后重试仍得到明确失败
    src.gate = None
    mgr.reload_for_unknown_kid(mgr.current(), "ghost-9")
    assert src.load_count == 2
    clock.advance(INTERVAL)
    with pytest.raises(ConnectionError):
        mgr.reload_for_unknown_kid(mgr.current(), "ghost-9")
    assert src.load_count == 3

    # 上游恢复后：下一个间隔的回源正常工作，负缓存/发布语义不受影响
    src.down = False
    clock.advance(INTERVAL)
    mgr.reload_for_unknown_kid(mgr.current(), "ghost-9")
    assert src.load_count == 4


# --------------------------------------------------------------------- #
# 场景 7（网关级）：伪造未知 kid 的令牌洪水，三段链路结论一致且读取有上限
# --------------------------------------------------------------------- #
def _forged_token(kid: str) -> str:
    import base64
    import hashlib
    import hmac
    import json

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "ZT1", "kid": kid},
                            separators=(",", ":"), sort_keys=True).encode())
    claims = b64(json.dumps({
        "sub": "mallory", "jti": "j-1",
        "iat": NOW.timestamp(), "exp": (NOW + dt.timedelta(minutes=5)).timestamp(),
        "roles": ["reader"], "attrs": {},
    }, separators=(",", ":"), sort_keys=True).encode())
    sig = b64(hmac.new(b"x", f"{header}.{claims}".encode(),
                       hashlib.sha256).digest())
    return f"{header}.{claims}.{sig}"


def test_gateway_unknown_kid_token_flood_bounded_and_consistent():
    src = MutableReleaseSource(_content())
    clock = FakeClock()
    mgr = _manager(src, capacity=16, clock=clock)
    gw = Gateway(released=mgr, clock=lambda: NOW)

    # 500 种未知 kid 各打 4 个请求：全部按 token_unknown_kid 拒绝
    for n in range(500):
        token = _forged_token(f"ghost-{n}")
        for _ in range(4):
            with pytest.raises(AuthError) as ei:
                gw.authorize(f"rq-{n}", token, "read", "db", now=NOW)
            assert ei.value.reason is DenyReason.TOKEN_UNKNOWN_KID
            assert ei.value.release_id == 1

    # 2000 个请求、500 种标识：真实读取收敛到 构造期 1 次 + 1 次
    assert src.load_count == 2
