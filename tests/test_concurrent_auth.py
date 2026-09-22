"""并发鉴权场景测试。

覆盖三类一致性：

1. **密钥轮换进行中的并发验签**：旧令牌（旧 kid）在重叠窗口内始终可验，
   新令牌（新 kid）发布后可验，任何线程都不出现"短暂失效"。
2. **策略热更新与判定并发**：判定期间替换策略，每个结论要么全按旧版本
   要么全按新版本，``policy_version`` 与结论自洽，绝不出现版本混用。
3. **高并发下单飞重载**：未知 kid 触发的重载真实拉取只发生一次。
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ztauth.keyring import Keyring, StaticKeySource, generate_key
from ztauth.policy import AuthzRequest, parse_policy
from ztauth.tokens import issue_token, verify_token


def _req() -> AuthzRequest:
    return AuthzRequest(principal="alice", action="read", resource="db",
                        attributes={"dept": "eng"})


def test_concurrent_verify_during_rotation_never_fails(clock_state) -> None:
    clock = lambda: clock_state["now"]
    clock_state["now"] = 900.0
    old = generate_key("kid-old", not_before=0.0, not_after=1000.0)
    new = generate_key("kid-new", not_before=1000.0, not_after=2000.0)
    source = StaticKeySource([old])
    keyring = Keyring(source, overlap_seconds=60.0, clock=clock)

    # 轮换前用旧密钥签发
    old_token, _ = issue_token(
        keyring, sub="alice", ttl_seconds=200, clock=clock
    )
    # 发布新密钥集合（重叠期保留旧密钥）
    source.set_keys([old, new])
    keyring.reload()
    clock_state["now"] = 1020.0  # 进入重叠窗口
    new_token, _ = issue_token(
        keyring, sub="alice", ttl_seconds=100, clock=clock
    )

    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        tok = old_token if i % 2 == 0 else new_token
        try:
            verify_token(tok, keyring, clock=clock)
            ok = True
        except Exception:
            ok = False
        with lock:
            outcomes.append(ok)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(worker, range(256)))

    assert len(outcomes) == 256
    assert all(outcomes), "no request may transiently fail during overlap rotation"


def test_concurrent_decisions_are_consistent_per_policy_version(
    gateway, make_token
) -> None:
    tok = make_token(gateway)
    store = gateway._test_policy_store

    # v1 允许 alice；v2 改为全拒绝
    v2 = parse_policy(
        {"version": 2, "rules": [
            {"id": "deny-all", "effect": "deny", "action": "read",
             "resource": "db"}]}
    )

    results: list[tuple[bool, int, str]] = []
    lock = threading.Lock()
    start = threading.Barrier(17)  # 16 workers + 1 reloader

    def authorize_worker() -> None:
        start.wait()
        r = gateway.authorize(tok, _req())
        with lock:
            results.append((r.allowed, r.policy_version, r.basis))

    def reload_worker() -> None:
        start.wait()
        store.replace(v2)  # 与判定并发发生；引擎下次 decide 自动发现

    threads = [threading.Thread(target=authorize_worker) for _ in range(16)]
    threads.append(threading.Thread(target=reload_worker))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 16
    # 一致性：允许的结论必须基于 v1，拒绝的结论必须基于 v2（版本不混用）
    for allowed, version, basis in results:
        if allowed:
            assert version == 1 and basis == "allow-alice-db"
        else:
            assert version == 2 and basis == "deny-all"
    # 热更新后稳态：全部 v2 拒绝
    steady = gateway.authorize(tok, _req())
    assert steady.allowed is False and steady.policy_version == 2


def test_concurrent_unknown_kid_single_flight_pulls_once() -> None:
    old = generate_key("kid-old")

    class SlowSource(StaticKeySource):
        def __init__(self, keys) -> None:
            super().__init__(keys)
            self.real_loads = 0
            self._barrier = threading.Barrier(24)

        def load(self):
            self.real_loads += 1
            import time
            time.sleep(0.1)
            return super().load()

    from ztauth.keyring import Keyring
    from ztauth.errors import TokenError

    src = SlowSource([old])
    keyring = Keyring(src, overlap_seconds=60.0)

    def worker() -> None:
        try:
            keyring.verify_key("kid-missing")
        except TokenError:
            pass

    with ThreadPoolExecutor(max_workers=24) as pool:
        list(pool.map(lambda _: worker(), range(24)))

    # 初始加载 1 次 + 并发 burst 合并为 1 次
    assert src.real_loads == 2
