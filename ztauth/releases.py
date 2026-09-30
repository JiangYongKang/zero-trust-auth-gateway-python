"""发布批次：密钥 / 策略 / 凭据作为不可变整体一起发布、回退与限期保留。

核心语义：
- publish 一次提交一批配置，返回唯一且单调递增的 release_id；指针原子切换，
  之后的新请求完整使用同一批次，不跨批次混用。
- rollback 只能回到仍在保留窗口内的历史批次；标识从未存在与已超保留期分别
  抛出 ReleaseNotFound / ReleaseExpired。
- 请求开始即 pin 住当时批次，淘汰不得移除仍有在途请求的批次。
- 同一批次的上游并发加载合并为一次（single-flight）；未知 kid 的源读取按
  "当前批次代际"限流，洪水请求也不会带来无界读取。
"""
from __future__ import annotations

import dataclasses
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol

from .credentials import Credential
from .keys import FrozenKeyRing, SigningKey
from .policy import Policy


@dataclasses.dataclass(frozen=True)
class ReleasePayload:
    """上游源给出的一次发布内容（不可变）。"""

    release_id: int
    keys: tuple[SigningKey, ...]
    key_version: int
    policy: Policy
    credentials: dict[str, Credential]


@dataclasses.dataclass(frozen=True)
class ReleaseBundle:
    """已被管理器采纳的批次：在 Payload 之外附一个可直接验签的只读密钥环。"""

    release_id: int
    key_version: int
    policy: Policy
    ring: FrozenKeyRing
    credentials: dict[str, Credential]

    @classmethod
    def from_payload(cls, payload: ReleasePayload) -> "ReleaseBundle":
        return cls(
            release_id=payload.release_id,
            key_version=payload.key_version,
            policy=payload.policy,
            ring=FrozenKeyRing(list(payload.keys), payload.key_version),
            credentials=dict(payload.credentials),
        )


class ReleaseSource(Protocol):
    """上游发布源：管理器只需要读取"最新批次"。"""

    def load_latest(self) -> ReleasePayload:
        ...


class MutableReleaseSource(ReleaseSource, Protocol):
    """可提交新批次的上游源（本地内存实现即此协议）。"""

    def publish(
        self,
        keys: tuple[SigningKey, ...],
        key_version: int,
        policy: Policy,
        credentials: dict[str, Credential],
    ) -> ReleasePayload:
        ...


class ReleaseNotFound(LookupError):
    """回退目标标识从未存在过（id 非法或高于已知高水位）。"""


class ReleaseExpired(LookupError):
    """回退目标确实发布过，但已超出保留窗口、被淘汰。"""


class InMemoryReleaseSource:
    """本地发布源：保存"最新批次"，发布 id 由源端单调分配。

    只保留最新一份内容（模拟配置中心：历史版本不在源端）；历史批次的内存
    保留由 ReleaseManager 负责。load_latest 计数用于验证读取上限。
    """

    def __init__(self, initial: ReleasePayload) -> None:
        if initial.release_id < 1:
            raise ValueError("release_id 必须从 1 开始")
        self._lock = threading.Lock()
        self._latest = initial
        self.load_count = 0

    def latest_id(self) -> int:
        return self._latest.release_id

    def publish(
        self,
        keys: tuple[SigningKey, ...],
        key_version: int,
        policy: Policy,
        credentials: dict[str, Credential],
    ) -> ReleasePayload:
        with self._lock:
            payload = ReleasePayload(
                release_id=self._latest.release_id + 1,
                keys=tuple(keys),
                key_version=key_version,
                policy=policy,
                credentials=dict(credentials),
            )
            self._latest = payload
            return payload

    def load_latest(self) -> ReleasePayload:
        self.load_count += 1
        return self._latest


class ReleaseManager:
    """发布批次管理器：原子切换、限期保留、确定性淘汰、读取 single-flight。

    并发放松说明：所有元数据（保留字典、当前指针、代际门闩、在途 pin）由一把
    锁保护，但锁内绝不调用上游源——真正的源读取在锁外完成，只借助事件做
    single-flight 合并，因此发布/回退不会长时间阻塞鉴权读路径。
    """

    def __init__(self, source: ReleaseSource, *, retain: int = 10) -> None:
        if retain < 1:
            raise ValueError("retain 必须 >= 1")
        self._source = source
        self._retain = retain
        self._lock = threading.Lock()
        first = source.load_latest()
        bundle = ReleaseBundle.from_payload(first)
        self._retained: dict[int, _Retained] = {
            first.release_id: _Retained(bundle),
        }
        self._current_id = first.release_id
        self._high_water = first.release_id
        self._latest_loaded_id = first.release_id
        # 未知 kid 代际门闩：记录上一次因未知 kid 检查上游时的当前批次；
        # 与当前批次相同则跳过，从而"每个当前代际至多读取一次上游"。
        self._unknown_checked_generation: int | None = None
        # 当前指针落后于上游（发生过回退）：未知 kid 不再自动向前采纳
        self._rolled_back = False
        self._inflight: threading.Event | None = None
        self._inflight_force_adopt = False

    # ---- 只读视图 ----------------------------------------------------------

    @property
    def current_id(self) -> int:
        with self._lock:
            return self._current_id

    @property
    def high_water(self) -> int:
        """曾经出现过的最大 release_id；用于区分"从未存在"。"""
        with self._lock:
            return self._high_water

    def current(self) -> ReleaseBundle:
        with self._lock:
            return self._retained[self._current_id].bundle

    def retained_ids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(self._retained)

    @contextmanager
    def use_current(self) -> Iterator[ReleaseBundle]:
        """pin 住进入时的当前批次；yield 期间该批次不会被淘汰。"""
        with self._lock:
            rid = self._current_id
            retained = self._retained[rid]
            retained.pins += 1
        try:
            yield retained.bundle
        finally:
            with self._lock:
                retained.pins -= 1
                if retained.pins == 0:
                    self._evict_locked()

    # ---- 发布 / 回退 --------------------------------------------------------

    def publish(
        self,
        keys: tuple[SigningKey, ...],
        key_version: int,
        policy: Policy,
        credentials: dict[str, Credential],
    ) -> int:
        """提交一批新配置；源端分配单调 id，管理器原子采纳为当前批次。"""
        publish = getattr(self._source, "publish", None)
        if not callable(publish):
            raise TypeError("当前 ReleaseSource 不支持 publish")
        payload = publish(keys, key_version, policy, credentials)
        with self._lock:
            self._register_locked(payload)
            self._current_id = payload.release_id
            self._rolled_back = False
            # 新批次成为当前：未知 kid 门闩复位（新一代可再检查一次上游）
            self._unknown_checked_generation = None
            return payload.release_id

    def rollback(self, release_id: int) -> int:
        """回退到仍在保留窗口内的历史批次；无需重启即对后续请求生效。

        - release_id 非法 / 高于已知高水位 -> ReleaseNotFound（从未存在）
        - 曾发布但已超保留期被淘汰 -> ReleaseExpired
        """
        with self._lock:
            if release_id < 1 or release_id > self._high_water:
                raise ReleaseNotFound(f"release_id={release_id}")
            if release_id not in self._retained:
                raise ReleaseExpired(f"release_id={release_id}")
            self._current_id = release_id
            self._rolled_back = release_id < self._latest_loaded_id
            # 回退后的目标代际视为"已检查"：未知 kid 不会借机自动向前拉新批次
            self._unknown_checked_generation = release_id
            return release_id

    def refresh(self) -> int:
        """显式拉取上游最新批次；比当前更新则采纳（同时清除回退态）。"""
        self._load_single_flight(force_adopt=True)
        with self._lock:
            self._rolled_back = False
            # 显式刷新后当前代际已与上游一致，未知 kid 无需再触发读取
            self._unknown_checked_generation = self._current_id
            return self._current_id

    def try_refresh_for_unknown_kid(self) -> int:
        """未知 kid 触发的受控刷新：每个当前代际至多读取一次源。

        回退态下不自动向前采纳；已有同代际在途加载则等待复用，绝不重复读取。
        返回调用后应使用的当前批次 id（调用方据此判断是否整请求重来）。
        """
        with self._lock:
            if self._rolled_back:
                return self._current_id
            if self._unknown_checked_generation == self._current_id:
                return self._current_id
            inflight = self._inflight

        if inflight is not None:
            inflight.wait()
            with self._lock:
                return self._current_id

        self._load_single_flight()
        with self._lock:
            # 无论上游是否真的更新，本次代际的检查额度已消耗
            self._unknown_checked_generation = self._current_id
            return self._current_id

    # ---- 内部 --------------------------------------------------------------

    def _load_single_flight(self, *, force_adopt: bool = False) -> ReleasePayload | None:
        """锁外读取上游；同一时刻仅一个线程真正 load，其余等待复用。

        返回 None 表示本线程是等待者（实际加载由别的线程完成）；非 None 为本
        线程亲自加载并已登记的内容。注册/采纳统一在加载者侧执行。
        force_adopt 用于显式 refresh：即便处于回退态也把指针提到最新批次。

        关键：event.wait() 必须在锁外，否则加载者无法重新获取锁完成登记。
        """
        with self._lock:
            existing = self._inflight
            if existing is None:
                event = threading.Event()
                self._inflight = event
                self._inflight_force_adopt = force_adopt
                is_loader = True
            else:
                event = existing
                if force_adopt:
                    self._inflight_force_adopt = True
                is_loader = False

        if not is_loader:
            # 锁外等待加载者完成，绝不在持锁时阻塞
            event.wait()
            if force_adopt:
                with self._lock:
                    if self._latest_loaded_id > self._current_id:
                        self._current_id = self._latest_loaded_id
            return None

        try:
            payload = self._source.load_latest()
        except BaseException:
            with self._lock:
                self._inflight = None
                # 失败也消耗本次代际门闩，避免源持续故障时洪水请求反复打源
                self._unknown_checked_generation = self._current_id
                event.set()
            raise
        with self._lock:
            self._register_locked(payload)
            if (self._inflight_force_adopt or not self._rolled_back) \
                    and payload.release_id > self._current_id:
                self._current_id = payload.release_id
            self._inflight = None
            event.set()
        return payload

    def _register_locked(self, payload: ReleasePayload) -> None:
        """登记新批次并推进水位；已是已知 id 则按内容不变忽略。"""
        rid = payload.release_id
        if rid > self._high_water:
            self._high_water = rid
        if rid > self._latest_loaded_id:
            self._latest_loaded_id = rid
        if rid not in self._retained:
            self._retained[rid] = _Retained(ReleaseBundle.from_payload(payload))
            self._evict_locked()

    def _evict_locked(self) -> None:
        """超出保留上限时按发布先后（FIFO）淘汰；当前/在途批次绝不淘汰。

        若所有候选都仍有在途请求，宁可暂时超容，等 pin 释放后再回收。
        """
        while len(self._retained) > self._retain:
            victim = None
            for rid, retained in self._retained.items():  # 插入序 = id 升序
                if rid == self._current_id or retained.pins > 0:
                    continue
                victim = rid
                break
            if victim is None:
                return
            del self._retained[victim]


@dataclasses.dataclass
class _Retained:
    bundle: ReleaseBundle
    pins: int = 0
