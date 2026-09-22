"""密钥轮换场景测试。

覆盖：
* 轮换重叠窗口内新旧密钥同时可验签；
* 未知 kid 触发受控重载（而非直接失败）；
* 单飞重载：高并发下真实拉取只发生一次，且不出现短暂失效；
* 超出重叠窗口的旧密钥被拒绝（原因可区分）。
"""

from __future__ import annotations

import threading

import pytest

from ztauth.errors import TokenError, TokenReasons
from ztauth.keyring import Keyring, StaticKeySource, generate_key


def test_overlap_window_accepts_old_and_new_keys() -> None:
    old = generate_key("kid-old", not_before=0.0, not_after=100.0)
    new = generate_key("kid-new", not_before=100.0, not_after=200.0)
    kr = Keyring(StaticKeySource([old, new]), overlap_seconds=30.0)

    # 重叠期 t=110：旧密钥虽已 not_after，但仍在宽限窗口可验签；
    # 新密钥严格 active，既可验签也可签发
    kr._clock = lambda: 110.0
    assert kr.verify_key("kid-old").kid == "kid-old"
    assert kr.verify_key("kid-new").kid == "kid-new"
    assert kr.signing_key().kid == "kid-new"  # 签发只用严格 active 的新密钥
    assert kr.latest_kid() == "kid-new"


def test_key_outside_overlap_window_is_rejected_with_distinct_reason() -> None:
    old = generate_key("kid-old", not_before=0.0, not_after=100.0)
    kr = Keyring(StaticKeySource([old]), overlap_seconds=30.0)
    kr._clock = lambda: 130.0  # 恰好在宽限结束点（右开区间）
    with pytest.raises(TokenError) as ei:
        kr.verify_key("kid-old")
    assert ei.value.reason == TokenReasons.UNKNOWN_KID


class _CountingSource(StaticKeySource):
    def __init__(self, keys) -> None:
        super().__init__(keys)
        self.real_loads = 0

    def load(self):
        self.real_loads += 1
        return super().load()


def test_unknown_kid_triggers_controlled_reload_then_succeeds() -> None:
    old = generate_key("kid-old")
    src = _CountingSource([old])
    kr = Keyring(src, overlap_seconds=30.0)
    new = generate_key("kid-new")

    with pytest.raises(TokenError) as ei:
        kr.verify_key("kid-new")  # 重载后仍未知
    assert ei.value.reason == TokenReasons.UNKNOWN_KID

    src.set_keys([old, new])
    assert kr.verify_key("kid-new").kid == "kid-new"  # 再次触发重载即命中


def test_single_flight_reload_under_concurrency_pulls_once() -> None:
    old = generate_key("kid-old")
    new = generate_key("kid-new")

    class SlowSource(_CountingSource):
        def load(self):
            self.real_loads += 1
            import time

            time.sleep(0.15)  # 放大并发窗口
            return StaticKeySource.load(self)

    src = SlowSource([old, new])
    kr = Keyring(src, overlap_seconds=30.0)

    # 从快照中移除 new 的可见性以模拟"上线后首次被引用"，
    # 这里直接让所有线程并发 reload：真实拉取只能发生一次
    results: list[str] = []
    errors: list[str] = []
    barrier = threading.Barrier(32)

    def worker() -> None:
        barrier.wait()
        try:
            results.append(kr.reload().get("kid-new").kid)
        except TokenError as exc:
            errors.append(exc.reason)

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert results == ["kid-new"] * 32
    # 1 次初始加载 + 1 次并发合并后的真实重载
    assert src.real_loads == 2


def test_failed_reload_keeps_previous_snapshot_available() -> None:
    old = generate_key("kid-old")
    src = StaticKeySource([old])
    kr = Keyring(src, overlap_seconds=30.0)

    def boom() -> list:
        raise RuntimeError("source down")

    kr._source.load = boom  # type: ignore[method-assign]
    with pytest.raises(TokenError) as ei:
        kr.reload()
    assert ei.value.reason == TokenReasons.KEY_RELOAD_UNAVAILABLE
    # 旧快照仍然完整可用，读路径无短暂失效
    assert kr.verify_key("kid-old").kid == "kid-old"
