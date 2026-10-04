"""未知 kid 持续冲击下，上游真实读取次数的确定上限。

业务背景：发布批次模式下，当前批次没有的 kid 会触发"受控回源"。若按 kid
记负缓存，攻击/异常流量只需让未知 kid 种类足够多且不断变化，就能把上游
配置源的真实读取次数打到无界（种类数 × 轮换轮次）。本组用例验证修复后的
时间闸门语义：

    上游内容不变时，任意时长 T 内真实读取次数 ≤ 2 + ⌊T / reload_cooldown⌋
    （含构造期的首次读取；每个冷却窗口至多回源一次）

与未知 kid 的种类数、请求总量、并发度均无关；合法的密钥更新（上游真的出
现新 kid）在冷却结束后的一次回源中即被发现并发布为新批次。

覆盖场景（运行 `uv run pytest tests/test_unknown_kid_read_bound.py -v
-o log_cli=true -o log_cli_level=INFO` 可在日志中看到各场景与读取计数）：
1. 未知标识种类远超单批规模（1000 种 vs 批内 1 把密钥）；
2. 种类数从几十到上千逐级放大，读取次数稳定在上限而不线性增长；
3. 同一批未知标识反复轮换多轮，第二轮/第三轮不再回源；
4. 并发同一标识：最多真实读取一次；
5. 并发互不相同的标识：读取次数不放大到并发量级；
6. 合法密钥更新仍被及时发现并对后续请求生效；
7. 上游失败：并发等待方拿到同一明确失败、不被挂住，闸门期内不重复打上游；
8. 时间推进下读取次数始终满足上限公式。
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import math
import threading

import pytest

from ztauth.credentials import Credential, CredentialVersion, VersionState
from ztauth.errors import AuthError, DenyReason
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import Policy, Rule
from ztauth.releases import ReleaseContent, ReleaseManager
from ztauth.sources import MutableReleaseSource
from ztauth.tokens import TokenIssuer

log = logging.getLogger("ztauth.tests.read_bound")

NOW = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)
COOLDOWN = 1.0


class FakeClock:
    """可手动推进的单调时钟：让"冷却期"在测试里确定性地生效。"""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _key(kid: str) -> SigningKey:
    return SigningKey(kid, f"secret-{kid}".encode(),
                      NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30),
                      "active")


def _content(kids: tuple[str, ...] = ("k1",), kv: int = 1) -> ReleaseContent:
    return ReleaseContent(
        keys=tuple(_key(k) for k in kids),
        policy=Policy(version=kv, rules=(
            Rule("p1", "allow", "read", "db",
                 require={"team": "payments"}, roles=("reader",)),
        )),
        credentials={"db": Credential("db", ("reader",), (
            CredentialVersion(1, b"cred-v1", VersionState.CURRENT, None),
        ))},
        keys_version=kv,
    )


def _manager(src: MutableReleaseSource, clock: FakeClock) -> ReleaseManager:
    return ReleaseManager(src, max_retained=8,
                          reload_cooldown=COOLDOWN, clock=clock)


def _flood(mgr: ReleaseManager, kids: list[str]) -> None:
    for kid in kids:
        mgr.reload_for_unknown_kid(mgr.current(), kid)


def test_bound_holds_when_unknown_kinds_far_exceed_batch_size():
    """场景 1：批内仅 1 把密钥，未知标识 1000 种持续冲击，读取收敛到上限。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)

    kids = [f"bogus-{i}" for i in range(1000)]
    _flood(mgr, kids)
    # 上限：构造期 1 次 + 闸门期内合并后恰好 1 次真实回源
    assert src.load_count == 2
    log.info("场景1 种类远超单批规模: kids=%d 批内密钥=1 真实读取=%d 上限=2",
             len(kids), src.load_count)


def test_bound_is_stable_as_unknown_kinds_scale_up():
    """场景 2：种类数 32 -> 2048 逐级放大，读取次数不随种类数增长。"""
    for n in (32, 128, 512, 2048):
        clock = FakeClock()
        src = MutableReleaseSource(_content(("k1",)))
        mgr = _manager(src, clock)
        _flood(mgr, [f"ghost-{i}" for i in range(n)])
        assert src.load_count == 2, f"kids={n} 时读取次数应稳定在上限"
        log.info("场景2 种类数扫描: kids=%d 真实读取=%d 上限=2", n, src.load_count)


def test_repeated_rotation_of_same_unknown_kids_reads_once():
    """场景 3：同一批未知标识反复轮换，第二轮、第三轮不再回源。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)

    kids = [f"rot-{i}" for i in range(300)]
    for round_no in range(1, 6):
        _flood(mgr, kids)
        assert src.load_count == 2, f"第 {round_no} 轮不应产生新的真实读取"
        log.info("场景3 反复轮换: 第%d轮 kids=%d 真实读取=%d 上限=2",
                 round_no, len(kids), src.load_count)


def test_concurrent_same_unknown_kid_reads_source_once():
    """场景 4：大量请求同时带同一个未知标识，最多真实读取一次。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)
    barrier = threading.Barrier(64)
    errors: list[Exception] = []

    def worker():
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(mgr.current(), "same-ghost")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert src.load_count == 2  # 构造期 1 次 + 64 并发合并为 1 次
    log.info("场景4 并发同标识: 并发=64 真实读取=%d 上限=2", src.load_count)


def test_concurrent_distinct_unknown_kids_do_not_amplify_reads():
    """场景 5：并发携带互不相同的未知标识，读取次数不放大到并发量级。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)
    barrier = threading.Barrier(64)
    errors: list[Exception] = []

    def worker(kid: str):
        barrier.wait()
        try:
            mgr.reload_for_unknown_kid(mgr.current(), kid)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"burst-{i}",))
               for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # 全局 single-flight + 时间闸门：64 个不同 kid 并发也只有 1 次真实回源
    assert src.load_count == 2
    log.info("场景5 并发不同标识: 并发=64(标识各异) 真实读取=%d 上限=2",
             src.load_count)


def test_legitimate_key_update_is_discovered_after_cooldown():
    """场景 6：限制读取不漏掉真正的新密钥——冷却结束后回源发现并发布。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",), kv=1))
    mgr = _manager(src, clock)
    gw = Gateway(released=mgr, clock=lambda: NOW)

    # 先用未知标识把闸门打满：此时上游尚未更新
    _flood(mgr, [f"noise-{i}" for i in range(200)])
    assert src.load_count == 2

    # 上游发布合法新密钥 k2（keys_version 前进）
    src.set_content(_content(("k1", "k2"), kv=2))
    # 冷却期内：不回源，新令牌暂按 token_unknown_kid 拒绝（有界陈旧）
    token_k2 = _issue("k2")
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-early", token_k2, "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_UNKNOWN_KID
    assert src.load_count == 2

    # 冷却结束：下一次未知 kid 请求触发回源，发现 k2 并原子发布为新批次
    clock.advance(COOLDOWN + 0.1)
    mgr.reload_for_unknown_kid(mgr.current(), "k2")
    assert src.load_count == 3
    assert mgr.current_id() == 2
    # 后续请求立即生效
    result = gw.authorize("rq-after", token_k2, "read", "db", now=NOW)
    assert result.release_id == 2
    log.info("场景6 合法更新: 冷却后发现新kid 真实读取=%d 新批次=%d",
             src.load_count, mgr.current_id())


def _issue(kid: str, sub: str = "alice") -> str:
    ring = KeyRing(_StaticKeys([_key(kid)], 1))
    return TokenIssuer(ring).issue(
        sub, ttl=dt.timedelta(minutes=10), roles=("reader",),
        attrs={"team": "payments"}, now=NOW,
    )


class _StaticKeys:
    def __init__(self, keys, version):
        self._keys, self._version = keys, version

    def load(self):
        return list(self._keys), self._version


def _forge_kid(kid: str) -> str:
    """把 k1 的合法令牌头改写成任意 kid（签名必然无效，先在 kid 解析处分流）。"""
    good = _issue("k1")
    h, c, s = good.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    header["kid"] = kid
    h2 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    return f"{h2}.{c}.{s}"


def test_gateway_flood_of_distinct_unknown_kids_is_bounded():
    """场景 5b（网关链路）：每个请求带不同未知标识，全部明确拒绝且读取有上限。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)
    gw = Gateway(released=mgr, clock=lambda: NOW)

    for i in range(500):
        with pytest.raises(AuthError) as ei:
            gw.authorize(f"rq-{i}", _forge_kid(f"attacker-{i}"),
                         "read", "db", now=NOW)
        # 结论与单项路径一致：确认不含 -> token_unknown_kid，且带发布标识
        assert ei.value.reason is DenyReason.TOKEN_UNKNOWN_KID
        assert ei.value.release_id == 1
    assert src.load_count == 2
    log.info("场景5b 网关层冲击: 请求=500(标识各异) 真实读取=%d 上限=2",
             src.load_count)


def test_source_failure_propagates_to_all_waiters_and_is_also_bounded():
    """场景 7：上游失败时并发等待方拿到同一明确失败，失败重试同样有上限。"""
    clock = FakeClock()

    class FlappingSource:
        def __init__(self) -> None:
            self.load_count = 0
            self._first = True

        def load(self) -> ReleaseContent:
            self.load_count += 1
            if self._first:
                self._first = False
                return _content(("k1",))
            raise ConnectionError("release source down")

    src = FlappingSource()
    mgr = ReleaseManager(src, reload_cooldown=COOLDOWN, clock=clock)
    gw = Gateway(released=mgr, clock=lambda: NOW)
    barrier = threading.Barrier(32)
    outcomes: list[DenyReason] = []
    lock = threading.Lock()

    def worker(i: int):
        barrier.wait()
        try:
            gw.authorize(f"rq-f-{i}", _forge_kid("ghost"), "read", "db", now=NOW)
        except AuthError as exc:
            with lock:
                outcomes.append(exc.reason)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), "等待上游结果的请求不得被挂住"
    # 所有并发请求（leader 与等待方）得到同一个明确失败，
    # 与单项路径的 token_key_reload_unavailable 结论一致
    assert outcomes == [DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE] * 32
    assert src.load_count == 2  # 构造期 1 次 + 合并回源 1 次
    # 闸门期内：失败被缓存，同样的请求立即得到同一失败，不再打到上游
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-f-again", _forge_kid("ghost"), "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE
    assert src.load_count == 2
    # 冷却到期后允许重试一次（上游仍失败 -> 仍是同一明确失败）
    clock.advance(COOLDOWN + 0.1)
    with pytest.raises(AuthError) as ei:
        gw.authorize("rq-f-retry", _forge_kid("ghost"), "read", "db", now=NOW)
    assert ei.value.reason is DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE
    assert src.load_count == 3
    log.info("场景7 上游失败: 并发=32 均得到reload_unavailable 真实读取=%d",
             src.load_count)


def test_read_count_never_exceeds_time_based_bound():
    """场景 8：时间持续推移 + 标识不断翻新，读取次数始终 ≤ 1 + ⌈T/冷却⌉。"""
    clock = FakeClock()
    src = MutableReleaseSource(_content(("k1",)))
    mgr = _manager(src, clock)

    total_requests = 0
    for step in range(20):
        _flood(mgr, [f"wave-{step}-{i}" for i in range(250)])
        total_requests += 250
        # 确定上限：构造期 1 次 + 每个冷却窗口至多 1 次真实回源
        bound = 2 + math.floor(clock.now / COOLDOWN)
        assert src.load_count <= bound, (
            f"t={clock.now:.1f}s 读取 {src.load_count} 超出上限 {bound}")
        clock.advance(COOLDOWN / 2)  # 半个冷却期推进一次，冲击更密
    log.info("场景8 上限公式: 请求=%d 标识种类=%d 真实读取=%d 公式上限=%d",
             total_requests, 20 * 250, src.load_count,
             2 + math.floor(clock.now / COOLDOWN))
    # 确定性收尾：总读取远小于请求量与标识种类数
    assert src.load_count <= 2 + math.floor(clock.now / COOLDOWN)
