"""发布批次：原子发布、回退区分、限期保留与确定性淘汰、在途 pin 保护。"""
from __future__ import annotations

import datetime as dt
import threading

import pytest

from ztauth.credentials import (
    Credential,
    CredentialVersion,
    InMemoryCredentialVault,
    VersionState,
)
from ztauth.keys import FrozenKeyRing, SigningKey
from ztauth.policy import Policy, Rule
from ztauth.releases import (
    InMemoryReleaseSource,
    ReleaseExpired,
    ReleaseManager,
    ReleaseNotFound,
    ReleasePayload,
)

NOW = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)


def _key(kid: str, secret: bytes = b"k") -> SigningKey:
    return SigningKey(
        kid, secret,
        NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30), "active",
    )


def _policy(v: int) -> Policy:
    return Policy(
        v,
        (Rule(f"r{v}", "allow", "read", "db",
              require={"v": str(v)}, roles=("reader",)),),
    )


def _cred(secret: bytes) -> dict[str, Credential]:
    return {
        "db": Credential(
            "db", ("reader",),
            (CredentialVersion(1, secret, VersionState.CURRENT, None),),
        ),
    }


def _payload(rid: int, secret: bytes = b"s") -> ReleasePayload:
    return ReleasePayload(
        rid, (_key(f"k{rid}", secret),), rid, _policy(rid), _cred(secret),
    )


@pytest.fixture
def source():
    return InMemoryReleaseSource(_payload(1, b"s1"))


@pytest.fixture
def manager(source):
    return ReleaseManager(source, retain=3)


# ---- 发布 ----------------------------------------------------------------

def test_publish_returns_monotonic_ids_and_switches_current(manager, source):
    assert manager.current_id == 1
    r2 = manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    r3 = manager.publish((_key("k3"),), 3, _policy(3), _cred(b"s3"))
    assert (r2, r3) == (2, 3)
    assert manager.current_id == 3
    assert manager.current().release_id == 3
    # 高水位单调
    assert manager.high_water == 3


def test_bundle_is_atomic_whole_no_mixing(manager):
    """同一批次内三件套版本对齐。"""
    manager.publish((_key("k2"),), 20, _policy(20), _cred(b"s20"))
    b = manager.current()
    assert b.release_id == 2
    assert b.key_version == 20
    assert b.policy.version == 20
    assert b.ring.version() == 20
    assert b.credentials["db"].versions[0].secret == b"s20"
    # FrozenKeyRing 不认识其他批次的 kid
    assert b.ring.lookup("k1").kind == "unknown"


def test_refresh_adopts_newer_upstream_release(source, manager):
    source.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    assert manager.current_id == 1  # 发布到源后，管理器尚未采纳
    assert manager.refresh() == 2
    assert manager.current_id == 2
    # 再 refresh 无新版本 -> 保持
    assert manager.refresh() == 2
    assert source.load_count == 3  # 构造期 1 次 + 两次显式 refresh 各 1 次


# ---- 回退 ----------------------------------------------------------------

def test_rollback_to_retained_takes_effect_without_restart(manager):
    manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    manager.publish((_key("k3"),), 3, _policy(3), _cred(b"s3"))
    assert manager.rollback(1) == 1
    assert manager.current().release_id == 1
    assert manager.current().credentials["db"].versions[0].secret == b"s1"
    # 回退到自己 = 幂等无操作
    assert manager.rollback(1) == 1


def test_rollback_unknown_vs_expired_are_distinct(manager):
    manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    manager.publish((_key("k3"),), 3, _policy(3), _cred(b"s3"))
    manager.publish((_key("k4"),), 4, _policy(4), _cred(b"s4"))  # retain=3 -> 淘汰 1

    assert manager.retained_ids() == (2, 3, 4)
    # 从未存在：非法值 / 高于高水位
    with pytest.raises(ReleaseNotFound):
        manager.rollback(0)
    with pytest.raises(ReleaseNotFound):
        manager.rollback(99)
    # 确实发布过，但已超保留期
    with pytest.raises(ReleaseExpired):
        manager.rollback(1)


def test_rollback_stays_even_when_newer_is_on_source(source, manager):
    manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    manager.rollback(1)
    # 上游仍有更新的批次，但回退态下未知 kid 不自动向前采纳
    assert manager.try_refresh_for_unknown_kid() == 1
    assert manager.current_id == 1
    # 显式 refresh 可重新向前
    assert manager.refresh() == 2


# ---- 保留与淘汰 -----------------------------------------------------------

def test_eviction_is_fifo_and_skips_current(manager):
    for i in range(2, 6):  # 发到 5，retain=3
        manager.publish((_key(f"k{i}"),), i, _policy(i), _cred(f"s{i}".encode()))
    assert manager.retained_ids() == (3, 4, 5)
    # 当前是 5；回退到 3 后再发 6：淘汰时跳过当前 3，淘汰最老的非当前 4
    manager.rollback(3)
    manager.publish((_key("k6"),), 6, _policy(6), _cred(b"s6"))
    assert manager.current_id == 6
    assert manager.retained_ids() == (3, 5, 6)


def test_eviction_never_removes_inflight_pinned_batch(source):
    manager = ReleaseManager(source, retain=2)
    manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    manager.publish((_key("k3"),), 3, _policy(3), _cred(b"s3"))
    # 此时保留 (2,3)，批次 1 已淘汰
    assert manager.retained_ids() == (2, 3)

    # pin 住批次 3，持续发布直到容量被打满：3 不得被淘汰
    entered = threading.Event()
    release_pin = threading.Event()
    evicted_during_pin: list[int] = []

    def holder():
        with manager.use_current():  # current=3
            entered.set()
            release_pin.wait()

    t = threading.Thread(target=holder)
    t.start()
    entered.wait()
    for i in range(4, 8):
        manager.publish((_key(f"k{i}"),), i, _policy(i), _cred(f"s{i}".encode()))
        evicted_during_pin.append(manager.retained_ids())
    assert any(3 in ids for ids in evicted_during_pin)
    assert 3 in manager.retained_ids()
    release_pin.set()
    t.join()
    # pin 释放后再次发布触发回收，3 作为最老非当前批次被淘汰
    manager.publish((_key("k8"),), 8, _policy(8), _cred(b"s8"))
    assert 3 not in manager.retained_ids()


def test_inflight_request_finishes_on_its_own_batch(manager):
    """pin 期间回退不影响已开始的请求看到的批次。"""
    manager.publish((_key("k2"),), 2, _policy(2), _cred(b"s2"))
    seen: list[int] = []
    entered = threading.Event()
    done = threading.Event()

    def request():
        with manager.use_current() as bundle:
            entered.set()
            done.wait(0.2)
            seen.append(bundle.release_id)

    t = threading.Thread(target=request)
    t.start()
    entered.wait()
    manager.rollback(1)
    done.set()
    t.join()
    assert seen == [2]


def test_retain_must_be_positive(source):
    with pytest.raises(ValueError):
        ReleaseManager(source, retain=0)
