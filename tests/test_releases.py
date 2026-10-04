"""发布批次：单调标识、同批一致、回退（两种错误可区分）、保留淘汰与在途保护。"""
from __future__ import annotations

import datetime as dt
import threading

import pytest

from ztauth.credentials import Credential, CredentialVersion, VersionState
from ztauth.keys import SigningKey
from ztauth.policy import Policy, Rule
from ztauth.releases import ReleaseContent, ReleaseError, ReleaseManager
from ztauth.sources import MutableReleaseSource

NOW = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)


def _key(kid: str, secret: bytes = b"k-secret") -> SigningKey:
    return SigningKey(kid, secret, NOW - dt.timedelta(days=1),
                      NOW + dt.timedelta(days=30), "active")


def _policy(v: int, attr: str) -> Policy:
    return Policy(version=v, rules=(
        Rule(f"r{v}", "allow", "read", "db",
             require={"v": attr}, roles=("reader",)),
    ))


def _cred(secret: bytes) -> dict:
    return {"db": Credential("db", ("reader",), (
        CredentialVersion(1, secret, VersionState.CURRENT, None),
    ))}


def _content(v: int, *, kid: str = "k1", secret: bytes = b"s1",
             kv: int = 1) -> ReleaseContent:
    return ReleaseContent(
        keys=(_key(kid),), policy=_policy(v, str(v)),
        credentials=_cred(secret), keys_version=kv,
    )


def test_publish_returns_monotonic_ids_and_current_switches():
    mgr = ReleaseManager(initial=_content(1))
    assert mgr.current().id == 1
    r2, r3 = mgr.publish(_content(2)), mgr.publish(_content(3))
    assert (r2, r3) == (2, 3)
    assert mgr.current_id() == 3
    with mgr.acquire() as rel:
        assert rel.content.policy.version == 3


def test_acquire_pins_release_for_whole_request_even_during_rollback():
    mgr = ReleaseManager(initial=_content(1))
    mgr.publish(_content(2))
    entered = threading.Event()
    release_inside: list[int] = []

    def hold():
        with mgr.acquire() as rel:
            entered.set()
            release_inside.append(rel.id)
            # 在途期间：发布 + 回退到 1
            mgr.publish(_content(3))
            mgr.rollback(1)
            release_inside.append(rel.content.policy.version)

    t = threading.Thread(target=hold)
    t.start()
    t.join()
    assert release_inside == [2, 2]  # 在途请求自始至终看到批次 2
    assert mgr.current_id() == 1     # 后续请求看到回退后的批次 1


def test_rollback_takes_effect_for_subsequent_requests():
    mgr = ReleaseManager(initial=_content(1))
    mgr.publish(_content(2))
    mgr.publish(_content(3))
    assert mgr.rollback(2) == 2
    assert mgr.current_id() == 2
    with mgr.acquire() as rel:
        assert rel.content.policy.version == 2


def test_rollback_never_existed_vs_retired_are_distinct():
    mgr = ReleaseManager(initial=_content(1), max_retained=2)
    mgr.publish(_content(2))
    mgr.publish(_content(3))  # 容量 2：批次 1 被淘汰
    assert mgr.retained_ids() == (2, 3)

    with pytest.raises(ReleaseError) as ei:
        mgr.rollback(999)  # 从未分配
    assert ei.value.kind == ReleaseError.NEVER_EXISTED
    assert ei.value.release_id == 999

    with pytest.raises(ReleaseError) as ei:
        mgr.rollback(1)  # 曾存在但已淘汰
    assert ei.value.kind == ReleaseError.RETIRED
    assert ei.value.release_id == 1


def test_eviction_is_oldest_first_but_current_and_inflight_are_protected():
    # 容量 2：发布 1,2,3 -> 淘汰最旧的 1
    mgr = ReleaseManager(initial=_content(1), max_retained=2)
    mgr.publish(_content(2))
    mgr.publish(_content(3))
    assert mgr.retained_ids() == (2, 3)

    # 持有批次 2 的在途请求；回退当前到 2 后再发 4。
    # 候选淘汰：3（最旧、非当前、无在途）-> 淘汰；在途的 2 不能提前淘汰，
    # 因此保留集合临时超限为 {2,3 之外...}：实际结果 {2,4} 前先验证 3 被淘汰、
    # 2 因在途保留。
    holder_ready = threading.Event()
    finish = threading.Event()

    def hold():
        mgr.rollback(2)
        with mgr.acquire() as rel:
            assert rel.id == 2
            holder_ready.set()
            finish.wait(2.0)

    t = threading.Thread(target=hold)
    t.start()
    holder_ready.wait(2.0)
    mgr.publish(_content(4))
    # 批次 3 被淘汰；在途的批次 2 被保留（即使它已非当前且最旧）
    assert mgr.retained_ids() == (2, 4)
    assert mgr.in_flight(2) == 1
    finish.set()
    t.join()
    # 在途结束后由后续发布补做淘汰：2 无在途保护后被清走，只留 4、5
    mgr.publish(_content(5))
    ids = mgr.retained_ids()
    assert ids == (4, 5)


def test_inflight_release_is_not_evicted_even_over_capacity():
    # 容量 1：持有批次 1 的在途请求时再发两个批次 -> 临时超限而不淘汰批次 1
    mgr = ReleaseManager(initial=_content(1), max_retained=1)
    done = threading.Event()

    def hold():
        with mgr.acquire():
            mgr.publish(_content(2))
            mgr.publish(_content(3))
            done.set()
            # 故意不退出，等待主线程确认保留集合
            release.wait(2.0)

    release = threading.Event()
    t = threading.Thread(target=hold)
    t.start()
    done.wait(2.0)
    assert 1 in mgr.retained_ids()          # 在途批次受保护
    assert mgr.in_flight(1) == 1
    release.set()
    t.join()
    # 在途结束后补做淘汰：非当前的旧批次可被清走，只留当前 3
    assert mgr.retained_ids() == (3,)


class _FakeClock:
    """可手动推进的单调时钟，用于确定性地验证回源时间闸门。"""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_unknown_kid_sustained_flood_reads_source_bounded_times():
    clock = _FakeClock()
    src = MutableReleaseSource(_content(1, kid="k1"))
    mgr = ReleaseManager(src, max_retained=4, reload_cooldown=1.0, clock=clock)

    # 8 个不同的未知 kid，每个被 16 个并发请求携带
    barrier = threading.Barrier(16)

    def worker(kid):
        barrier.wait()
        rel = mgr.current()
        mgr.reload_for_unknown_kid(rel, kid)

    threads = []
    for n in range(8):
        for _ in range(16):
            threads.append(threading.Thread(target=worker, args=(f"bogus-{n}",)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 全局 single-flight + 时间闸门：128 个并发请求合并为恰好 1 次真实读取
    assert src.load_count == 2  # 构造期 1 次 + 合并回源 1 次
    # 闸门期内：同一批 kid 反复轮换、再涌入新 kid，都不再回源
    for _ in range(3):
        for n in range(8):
            mgr.reload_for_unknown_kid(mgr.current(), f"bogus-{n}")
    for n in range(100):
        mgr.reload_for_unknown_kid(mgr.current(), f"fresh-{n}")
    assert src.load_count == 2
    # 冷却结束后才允许下一次真实回源（也仅一次）
    clock.advance(1.1)
    mgr.reload_for_unknown_kid(mgr.current(), "bogus-0")
    assert src.load_count == 3


def test_unknown_kid_reload_publishes_new_batch_but_caller_stays_pinned():
    src = MutableReleaseSource(_content(1, kid="k1"))
    mgr = ReleaseManager(src, max_retained=4)
    pinned = mgr.current()
    src.set_content(_content(2, kid="k2", kv=2))
    mgr.reload_for_unknown_kid(pinned, "k2")
    # 上游已就绪 -> 新批次发布，后续请求可见
    assert mgr.current_id() == 2
    # 但发起的那次仍固定在批次 1，批次 1 视图下 k2 仍未知
    view_kids = {k.kid for k in pinned.content.keys}
    assert view_kids == {"k1"}


def test_concurrent_unknown_kid_single_flight_per_batch():
    src = MutableReleaseSource(_content(1, kid="k1"))
    mgr = ReleaseManager(src)
    barrier = threading.Barrier(32)
    errors: list[Exception] = []

    def worker():
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(mgr.current(), "ghost")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker) for _ in range(32)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    # 构造期读取 1 次 + 32 并发合并为 1 次
    assert src.load_count == 2
    # 负缓存命中后仍然不读取
    mgr.reload_for_unknown_kid(mgr.current(), "ghost")
    assert src.load_count == 2


def test_reload_gate_is_time_based_not_per_kid():
    clock = _FakeClock()
    src = MutableReleaseSource(_content(1))
    mgr = ReleaseManager(src, reload_cooldown=1.0, clock=clock)
    rel = mgr.current()
    # 闸门期内：再多的不同未知 kid 也只产生一次真实读取（与种类数无关）
    for kid in ("a", "b", "c"):
        mgr.reload_for_unknown_kid(rel, kid)
    assert src.load_count == 1 + 1
    # 同一批 kid 反复轮换也不会再次回源（旧实现中 LRU 淘汰会在此回源）
    for _ in range(5):
        for kid in ("a", "b", "c"):
            mgr.reload_for_unknown_kid(rel, kid)
    assert src.load_count == 1 + 1
    # 冷却到期：下一个未知 kid 触发且仅触发一次新的真实读取
    clock.advance(1.1)
    mgr.reload_for_unknown_kid(rel, "a")
    assert src.load_count == 1 + 2
    mgr.reload_for_unknown_kid(rel, "b")
    assert src.load_count == 1 + 2
    # 发布新批次复位闸门：新批次可能带来此前未知的 kid，允许立即回源一次
    mgr.publish(_content(2, kid="k1"))
    mgr.reload_for_unknown_kid(mgr.current(), "c")
    assert src.load_count == 1 + 3


def test_legacy_single_component_rotation_orthogonal_to_releases():
    """发布批次与原有 KeyRing/PolicyStore/Vault 单项轮换互不影响。"""
    from ztauth.keys import KeyRing
    from ztauth.policy import PolicyStore
    from ztauth.credentials import InMemoryCredentialVault

    # 原有三件套仍然独立可用
    src = MutableReleaseSource(_content(1))
    key_src = __import__("ztauth.sources", fromlist=["MutableKeySource"]).MutableKeySource(
        [_key("kx")], 1)
    ring = KeyRing(key_src)
    store = PolicyStore(_PolicyOnly(_policy(1, "payments")))
    vault = InMemoryCredentialVault(_cred(b"legacy"))
    assert ring.version() == 1
    assert store.current().version == 1
    # 发布管理器独立运作，不触碰上面三个对象
    mgr = ReleaseManager(src, max_retained=3)
    mgr.publish(_content(2))
    assert mgr.current_id() == 2
    assert store.current().version == 1 and ring.version() == 1


class _PolicyOnly:
    def __init__(self, policy):
        self._p = policy

    def load(self):
        return self._p
