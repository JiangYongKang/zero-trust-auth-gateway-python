"""发布批次（release batches）：把密钥集合、策略、凭据库作为一个整体发布。

语义：
- publish 一次提交完整的 ReleaseContent（密钥+策略+凭据），得到唯一且单调
  递增的发布标识（从 1 开始）。批次对象不可变。
- 每个请求通过 acquire() 固定开始时的当前批次；三段链路都在该批次对象上
  完成，写操作（发布/回退）只改变"当前指针"，不影响已在途的请求。
- rollback(rid) 把当前指针移到保留期内的历史批次，立即对后续请求生效；
  rid 从未分配过 -> "never_existed"，曾分配但已淘汰 -> "retired"，两者
  通过 ReleaseError.kind 可区分。
- 保留上限 max_retained：超限时按发布标识升序（最旧优先）淘汰；当前批次
  与仍有在途请求（引用计数 > 0）的批次不得淘汰，因此容量可能临时超限，
  等在途请求结束后再次尝试淘汰。
- 未知 kid 的受控回源：全局 single-flight（并发请求——无论 kid 相同或不同——
  合并为一次真正的 ReleaseSource.load），double-check 后复用；有界 LRU 负缓存
  记录"已确认不含"的 kid；再加回源节流（reload_min_interval）：两次真实读取
  之间至少间隔一个时间窗口。三者叠加保证：未知 kid 持续冲击下，对上游的真实
  读取次数 <= 1 + 经过时间 / 间隔，与未知标识的种类数和请求总量无关；合法
  密钥更新最迟在一个间隔后被发现。回源读到含该 kid 的新整批内容时，将其作为
  一个新批次原子发布；发起请求本身仍按其开始时固定的批次给出结论（不跨批）。
"""
from __future__ import annotations

import contextlib
import dataclasses
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from typing import Protocol

from .credentials import Credential
from .keys import SigningKey
from .policy import Policy


@dataclasses.dataclass(frozen=True)
class ReleaseContent:
    """一次发布的完整内容：密钥 + 策略 + 凭据，三者同批生效。"""

    keys: tuple[SigningKey, ...]
    policy: Policy
    credentials: dict[str, Credential]
    keys_version: int = 0


@dataclasses.dataclass(frozen=True)
class Release:
    """不可变发布批次。"""

    id: int
    content: ReleaseContent


class ReleaseSource(Protocol):
    """上游配置源：一次性读出完整的一批配置。"""

    def load(self) -> ReleaseContent:
        ...


class ReleaseError(Exception):
    """发布管理操作失败。

    kind 取值：
    - "never_existed"：发布标识从未被分配过；
    - "retired"：批次曾存在，但已超出保留期被淘汰；
    - "empty"：尚未发布过任何批次。
    """

    NEVER_EXISTED = "never_existed"
    RETIRED = "retired"
    EMPTY = "empty"

    def __init__(self, kind: str, release_id: int | None = None) -> None:
        self.kind = kind
        self.release_id = release_id
        super().__init__(
            f"release {release_id} {kind}" if release_id is not None else kind
        )

    @classmethod
    def never_existed(cls, release_id: int) -> "ReleaseError":
        return cls(cls.NEVER_EXISTED, release_id)

    @classmethod
    def retired(cls, release_id: int) -> "ReleaseError":
        return cls(cls.RETIRED, release_id)


class _BoundedNegativeCache:
    """有界 LRU：记录"已向上游确认不含"的 kid 及确认时刻。

    条目只在确认后的 ttl 窗口内被视为有效；过期后再次出现允许重新回源，
    因此上游后来补发的合法密钥不会被陈旧的否定结论永久挡住。
    """

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("negative_cache_size must be >= 1")
        self._capacity = capacity
        self._items: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def is_fresh(self, key: str, now: float, ttl: float) -> bool:
        """key 在缓存中且确认时刻距今不足 ttl 才算命中。"""
        with self._lock:
            ts = self._items.get(key)
            if ts is None or now - ts >= ttl:
                return False
            self._items.move_to_end(key)
            return True

    def add(self, key: str, ts: float) -> None:
        with self._lock:
            self._items[key] = ts
            self._items.move_to_end(key)
            while len(self._items) > self._capacity:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


@dataclasses.dataclass
class _InflightReload:
    event: threading.Event
    error: BaseException | None = None


class ReleaseManager:
    """发布批次的发布、回退、保留、在途引用与受控回源。"""

    def __init__(
        self,
        source: ReleaseSource | None = None,
        *,
        initial: ReleaseContent | None = None,
        max_retained: int = 8,
        negative_cache_size: int = 256,
        reload_min_interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_retained < 1:
            raise ValueError("max_retained must be >= 1")
        if reload_min_interval < 0:
            raise ValueError("reload_min_interval must be >= 0")
        if source is None and initial is None:
            raise ValueError("either source or initial content is required")
        self._source = source
        self._max_retained = max_retained
        self._negative = _BoundedNegativeCache(negative_cache_size)
        self._reload_min_interval = float(reload_min_interval)
        self._clock = clock

        self._lock = threading.Lock()          # 保护下列全部状态（临界区都很短）
        self._retained: dict[int, Release] = {}
        self._refs: dict[int, int] = {}
        self._next_id = 1
        self._current: Release | None = None
        # 未知 kid 受控回源：全局 single-flight + 节流
        self._inflight: _InflightReload | None = None
        self._last_reload_at: float | None = None

        if initial is not None:
            self._commit_locked(initial)
        elif source is not None:
            # 仅给源时：构造期读取一次作为发布标识 1 的初始批次
            self._commit_locked(source.load())

    # ------------------------------------------------------------------ #
    # 发布 / 回退 / 读取
    # ------------------------------------------------------------------ #
    def publish(self, content: ReleaseContent | None = None) -> int:
        """提交一批新配置并返回其单调递增的发布标识。

        content 为 None 时从 ReleaseSource 读取；批次在锁内整体提交，
        读线程永远只能看到完整的批次，绝不出现配置短暂为空。
        """
        if content is None:
            if self._source is None:
                raise ValueError("no release source configured")
            content = self._source.load()
        with self._lock:
            rid = self._commit_locked(content)
            self._negative.clear()  # 新批次可能带来此前未知的 kid
            self._last_reload_at = None  # 新批次后允许立即再回源一次
            self._evict_locked()
            return rid

    def _commit_locked(self, content: ReleaseContent) -> int:
        rid = self._next_id
        self._next_id += 1
        release = Release(id=rid, content=content)
        self._retained[rid] = release
        self._current = release
        return rid

    def rollback(self, release_id: int) -> int:
        """把当前批次切换为保留期内的历史批次，返回生效标识。"""
        with self._lock:
            target = self._retained.get(release_id)
            if target is None:
                # 标识落在已分配区间内却不在保留集合 -> 曾存在但已淘汰
                if 1 <= release_id < self._next_id:
                    raise ReleaseError.retired(release_id)
                raise ReleaseError.never_existed(release_id)
            self._current = target
            return release_id

    def current(self) -> Release:
        """当前批次（原子引用读，不与写操作互斥）。"""
        release = self._current
        if release is None:
            raise ReleaseError(ReleaseError.EMPTY)
        return release

    def current_id(self) -> int:
        return self.current().id

    @contextlib.contextmanager
    def acquire(self) -> Iterator[Release]:
        """固定本次请求使用的批次，直到 with 块结束才允许淘汰该批次。"""
        release = self.current()  # 无锁获取不可变引用
        with self._lock:
            self._refs[release.id] = self._refs.get(release.id, 0) + 1
        try:
            yield release
        finally:
            with self._lock:
                count = self._refs[release.id] - 1
                if count > 0:
                    self._refs[release.id] = count
                else:
                    del self._refs[release.id]
                # 在途请求结束后，补做此前被引用挡住的淘汰
                self._evict_locked()

    def retained_ids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(sorted(self._retained))

    def in_flight(self, release_id: int) -> int:
        with self._lock:
            return self._refs.get(release_id, 0)

    # ------------------------------------------------------------------ #
    # 淘汰：标识升序（最旧优先），跳过当前批次与在途批次
    # ------------------------------------------------------------------ #
    def _evict_locked(self) -> None:
        while len(self._retained) > self._max_retained:
            current_id = self._current_id_locked()
            candidates = [
                rid for rid in self._retained
                if rid != current_id and self._refs.get(rid, 0) == 0
            ]
            if not candidates:
                # 全部批次仍在途或即当前批次：宁可临时超限也不提前淘汰
                return
            del self._retained[min(candidates)]  # 最旧优先

    def _current_id_locked(self) -> int:
        assert self._current is not None
        return self._current.id

    # ------------------------------------------------------------------ #
    # 未知 kid：全局 single-flight 受控回源 + 有界负缓存 + 回源节流
    # ------------------------------------------------------------------ #
    def reload_for_unknown_kid(self, release: Release, kid: str) -> None:
        """当前批次缺少 kid 时的受控回源。

        读取次数上限（确定、可断言）：
            真实 load 次数 <= 1 + 经过时间 / reload_min_interval
        与未知 kid 的种类数、请求总量、负缓存容量均无关。

        - 负缓存命中（确认时刻距今不足一个间隔）：直接返回，不回源；
          否定结论过期后自动失效，上游后来补发的合法密钥不会被永久挡住；
        - 已有一次回源在途：等待其结束并复用结果（无论 kid 是否相同——
          一次 load 读出的是整批内容，天然覆盖所有 kid）；
        - 距上次真实回源不足 reload_min_interval：直接返回，按未知处理；
          该 kid 不写入负缓存，因此间隔过后再次出现仍会触发真实回源，
          合法的新密钥最迟在一个间隔后被发现；
        - 源内容含该 kid 且不旧于当前密钥集合：作为新批次原子发布
          （调用方请求仍用原批次判定）；
        - 源内容不含：连同确认时刻记入有界负缓存；
        - 源异常：向上抛出，所有并发等待方得到同一异常，不会被挂住。
        """
        now = self._clock()
        if self._negative.is_fresh(kid, now, self._reload_min_interval):
            return
        with self._lock:
            now = self._clock()
            if self._negative.is_fresh(kid, now, self._reload_min_interval):
                return
            if self._inflight is not None:
                inflight = self._inflight
                leader = False
            else:
                if (
                    self._last_reload_at is not None
                    and now - self._last_reload_at < self._reload_min_interval
                ):
                    return  # 节流窗口内：不回源，按未知处理（不入负缓存）
                inflight = _InflightReload(event=threading.Event())
                self._inflight = inflight
                self._last_reload_at = now  # 无论成败都占住本窗口，保证上限
                leader = True

        if not leader:
            inflight.event.wait()
            if inflight.error is not None:
                raise inflight.error
            return

        try:
            if self._source is None:
                raise ConnectionError("no release source for controlled reload")
            content = self._source.load()
            with self._lock:
                stale = content.keys_version < self._current.content.keys_version
            if not stale and any(k.kid == kid for k in content.keys):
                # 上游已就绪且不旧于当前密钥集合：原子发布为新批次；
                # 当前请求仍固定在旧批次。陈旧内容（含 kid）视为源尚未更新，
                # 不产生新批次，直接走负缓存。
                self.publish(content)
            else:
                self._negative.add(kid, self._clock())
            inflight.error = None
        except BaseException as exc:  # 通知全部等待方，包括异常
            inflight.error = exc
            raise
        finally:
            with self._lock:
                if self._inflight is inflight:
                    self._inflight = None
            inflight.event.set()
