"""签名密钥集合：重叠窗口轮换 + 未知 kid 受控重载（single-flight）。

并发语义：
- 内部持有不可变快照 Snapshot，重载成功后在锁内原子替换，读线程永远看到
  一份完整的旧集合或新集合，不会出现重载中途的"短暂失效"。
- 未知 kid 触发的重载在锁内 double-check：同一时刻只有一个线程真正调用
  KeySource.load，其余线程等待后直接复用新快照，不会重复拉取。
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import threading
from typing import Literal, Protocol


@dataclasses.dataclass(frozen=True)
class SigningKey:
    kid: str
    secret: bytes
    not_before: dt.datetime  # UTC, inclusive
    not_after: dt.datetime   # UTC, exclusive
    state: str               # "active" | "retiring"


@dataclasses.dataclass(frozen=True)
class _Snapshot:
    version: int
    keys: dict[str, SigningKey]


@dataclasses.dataclass(frozen=True)
class LookupResult:
    kind: Literal["found", "unknown", "outside_window"]
    key: SigningKey | None = None


class KeySource(Protocol):
    def load(self) -> tuple[list[SigningKey], int]:
        """返回 (密钥列表, 密钥集合版本号)。版本号必须单调递增。"""
        ...


class FrozenKeyRing:
    """只读不可变密钥环：发布批次内的固定密钥集，不会触发任何重载。

    接口是 KeyRing 的只读子集（lookup / find / version / current_signing_key），
    因此可直接传给 TokenVerifier / TokenIssuer。
    """

    def __init__(self, keys: list[SigningKey], version: int) -> None:
        self._version = version
        self._keys: dict[str, SigningKey] = {k.kid: k for k in keys}

    def version(self) -> int:
        return self._version

    def _within_window(self, key: SigningKey, now: dt.datetime) -> bool:
        return key.not_before <= now < key.not_after

    def lookup(self, kid: str, *, now: dt.datetime | None = None) -> LookupResult:
        now = now or dt.datetime.now(dt.timezone.utc)
        key = self._keys.get(kid)
        if key is None:
            return LookupResult("unknown")
        if self._within_window(key, now):
            return LookupResult("found", key)
        return LookupResult("outside_window", key)

    def find(self, kid: str, *, now: dt.datetime | None = None) -> SigningKey | None:
        result = self.lookup(kid, now=now)
        return result.key if result.kind == "found" else None

    def current_signing_key(self, *, now: dt.datetime | None = None) -> SigningKey:
        now = now or dt.datetime.now(dt.timezone.utc)
        candidates = [
            k for k in self._keys.values()
            if k.state == "active" and self._within_window(k, now)
        ]
        if not candidates:
            raise RuntimeError("no active signing key within validity window")
        return max(candidates, key=lambda k: k.not_before)


class KeyRing:
    def __init__(self, source: KeySource) -> None:
        self._source = source
        self._lock = threading.Lock()
        keys, version = source.load()
        self._snapshot = _Snapshot(version=version, keys={k.kid: k for k in keys})

    def _within_window(self, key: SigningKey, now: dt.datetime) -> bool:
        return key.not_before <= now < key.not_after

    def _lookup(self, kid: str, now: dt.datetime, *, allow_reload: bool) -> LookupResult:
        snap = self._snapshot  # 原子引用读
        key = snap.keys.get(kid)
        if key is not None:
            if self._within_window(key, now):
                return LookupResult("found", key)
            return LookupResult("outside_window", key)
        if not allow_reload:
            return LookupResult("unknown")
        # 未知 kid：受控重载，single-flight + double-check
        with self._lock:
            snap = self._snapshot
            key = snap.keys.get(kid)
            if key is not None:  # 别的线程已完成重载
                if self._within_window(key, now):
                    return LookupResult("found", key)
                return LookupResult("outside_window", key)
            self._load_locked()
            key = self._snapshot.keys.get(kid)
            if key is None:
                return LookupResult("unknown")
            if self._within_window(key, now):
                return LookupResult("found", key)
            return LookupResult("outside_window", key)

    def _load_locked(self) -> None:
        keys, version = self._source.load()
        # 版本单调，拒绝降级
        if version < self._snapshot.version:
            return
        new_snap = _Snapshot(version=version, keys={k.kid: k for k in keys})
        self._snapshot = new_snap  # 锁内原子替换

    def find(self, kid: str, *, now: dt.datetime | None = None) -> SigningKey | None:
        """按 kid 查找窗口内有效密钥；未知 kid 会触发一次受控重载。"""
        now = now or dt.datetime.now(dt.timezone.utc)
        result = self._lookup(kid, now, allow_reload=True)
        return result.key if result.kind == "found" else None

    def lookup(self, kid: str, *, now: dt.datetime | None = None) -> LookupResult:
        """同 find，但区分 unknown / outside_window，供校验层给出拒绝原因。"""
        now = now or dt.datetime.now(dt.timezone.utc)
        return self._lookup(kid, now, allow_reload=True)

    def reload(self) -> int:
        with self._lock:
            self._load_locked()
            return self._snapshot.version

    def version(self) -> int:
        return self._snapshot.version

    def current_signing_key(self, *, now: dt.datetime | None = None) -> SigningKey:
        """挑选用于签发的当前密钥：active 且在窗口内，not_before 最新者优先。"""
        now = now or dt.datetime.now(dt.timezone.utc)
        snap = self._snapshot
        candidates = [
            k for k in snap.keys.values()
            if k.state == "active" and self._within_window(k, now)
        ]
        if not candidates:
            raise RuntimeError("no active signing key within validity window")
        return max(candidates, key=lambda k: k.not_before)

    def snapshot(self) -> tuple[tuple[SigningKey, ...], int]:
        """当前不可变快照 (密钥元组, 版本号)，用于打包发布批次。"""
        snap = self._snapshot
        return tuple(snap.keys.values()), snap.version
