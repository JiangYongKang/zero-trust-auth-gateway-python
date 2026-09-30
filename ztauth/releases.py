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
- 未知 kid 的受控回源：per-kid single-flight（并发合并为一次真正的
  ReleaseSource.load），double-check 后复用；另有有界 LRU 负缓存，保证
  大量"当前批次不存在的 kid"持续冲击时，对上游的真实读取次数有确定上限。
  回源读到含该 kid 的新整批内容时，将其作为一个新批次原子发布；发起请求
  本身仍按其开始时固定的批次给出结论（不跨批）。
"""
from __future__ import annotations

import contextlib
import dataclasses
import threading
from collections import OrderedDict
from collections.abc import Iterator
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
    """有界 LRU：记录"已向上游确认不含"的 kid，阻止重复/无界回源。"""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("negative_cache_size must be >= 1")
        self._capacity = capacity
        self._items: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def contains(self, key: str) -> bool:
        with self._lock:
            if key not in self._items:
                return False
            self._items.move_to_end(key)
            return True

    def add(self, key: str) -> None:
        with self._lock:
            self._items[key] = None
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
    ) -> None:
        if max_retained < 1:
            raise ValueError("max_retained must be >= 1")
        if source is None and initial is None:
            raise ValueError("either source or initial content is required")
        self._source = source
        self._max_retained = max_retained
        self._negative = _BoundedNegativeCache(negative_cache_size)

        self._lock = threading.Lock()          # 保护下列全部状态（临界区都很短）
        self._retained: dict[int, Release] = {}
        self._refs: dict[int, int] = {}
        self._next_id = 1
        self._current: Release | None = None
        # per-kid 受控回源合并
        self._reloading: dict[str, _InflightReload] = {}

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
    # 未知 kid：per-kid single-flight 受控回源 + 有界负缓存
    # ------------------------------------------------------------------ #
    def reload_for_unknown_kid(self, release: Release, kid: str) -> None:
        """当前批次缺少 kid 时的受控回源。

        - 负缓存命中：直接返回（调用方仍按原批次判 unknown，不会回源）；
        - 同一 kid 的并发调用合并为一次真正的 source.load；
        - 源内容含该 kid：作为新批次原子发布（调用方请求仍用原批次判定）；
        - 源内容不含：记入有界负缓存；
        - 源异常：向上抛出，所有并发等待方得到同一异常。
        """
        if self._negative.contains(kid):
            return
        with self._lock:
            if self._negative.contains(kid):
                return
            inflight = self._reloading.get(kid)
            if inflight is None:
                inflight = _InflightReload(event=threading.Event())
                self._reloading[kid] = inflight
                leader = True
            else:
                leader = False

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
                self._negative.add(kid)
            inflight.error = None
        except BaseException as exc:  # 通知全部等待方，包括异常
            inflight.error = exc
            raise
        finally:
            with self._lock:
                self._reloading.pop(kid, None)
            inflight.event.set()
