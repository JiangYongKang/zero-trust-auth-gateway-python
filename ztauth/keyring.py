"""签名密钥环：多版本密钥、轮换重叠窗口与受控重载。

语义约定
========

* 每个密钥 :class:`Key` 携带 ``kid``、对称校验材料 ``secret`` 以及
  激活窗口 ``[not_before, not_after)``。
* **轮换重叠窗口**：旧密钥到达 ``not_after`` 后，在 ``overlap_seconds``
  宽限期内仍可用于 *验签*（``usable_for_verify``），但不会再用于签发；
  新密钥在其 ``not_before`` 起即可用。因此轮换期间新旧密钥被同时接受，
  且边界完全由时间戳确定，无歧义。
* **未知 kid 的受控重载**：验签遇到未知 ``kid`` 不会立即判失败，而是触发
  一次 reload；reload 后仍未知才判定 ``unknown_kid``。
* **单飞（single-flight）重载**：并发请求触发的重载只会真正拉取一次，
  其余请求等待同一结果；重载失败时保留旧快照，读路径不出现短暂失效。
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from ztauth.errors import AuthError, TokenError, TokenReasons


@dataclass(frozen=True, slots=True)
class Key:
    """一个验签密钥（对称 HMAC 场景下 secret 即共享秘密）。"""

    kid: str
    secret: bytes
    not_before: float = 0.0
    not_after: float = float("inf")

    def active_at(self, ts: float | None = None) -> bool:
        """密钥在给定时间点是否处于其声明的激活窗口内。"""
        ts = time.time() if ts is None else ts
        return self.not_before <= ts < self.not_after

    def usable_for_verify(
        self, ts: float | None = None, *, overlap_seconds: float = 0.0
    ) -> bool:
        """是否可用于验签。

        与 :meth:`active_at` 的区别：验签额外接受 ``overlap_seconds``
        的轮换重叠宽限期，保证旧令牌在轮换边界仍能被校验。
        """
        ts = time.time() if ts is None else ts
        return self.not_before <= ts < (self.not_after + overlap_seconds)


@dataclass(frozen=True, slots=True)
class KeyringSnapshot:
    """密钥集合的不可变快照，读路径无锁共享。"""

    keys: dict[str, Key] = field(default_factory=dict)
    version: int = 0

    def get(self, kid: str) -> Key | None:
        return self.keys.get(kid)


class KeySource(Protocol):
    """密钥材料来源（本地生成或本地文件，测试中可直接构造）。"""

    def load(self) -> list[Key]:
        """返回当前应保留的密钥集合（含重叠期内的旧密钥）。"""
        ...


def generate_key(
    kid: str,
    *,
    not_before: float = 0.0,
    not_after: float = float("inf"),
    secret: bytes | None = None,
) -> Key:
    """生成本地随机密钥材料（仅使用进程本地熵，无外部依赖）。"""
    return Key(
        kid=kid,
        secret=secret if secret is not None else secrets.token_bytes(32),
        not_before=not_before,
        not_after=not_after,
    )


class StaticKeySource:
    """内存密钥来源：测试与本地演示用，可原子替换/轮换密钥集合。"""

    def __init__(self, keys: Iterable[Key] = ()) -> None:
        self._keys: list[Key] = list(keys)
        self._version = 0

    def set_keys(self, keys: Iterable[Key]) -> None:
        self._keys = list(keys)
        self._version += 1

    @property
    def load_count(self) -> int:
        return self._version

    def load(self) -> list[Key]:
        # 返回副本，避免调用方变更影响来源
        return list(self._keys)


class Keyring:
    """并发安全、支持重叠轮换与单飞重载的密钥环。"""

    def __init__(
        self,
        source: KeySource,
        *,
        overlap_seconds: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._overlap = float(overlap_seconds)
        self._clock = clock

        self._snapshot: KeyringSnapshot | None = None
        self._lock = threading.Lock()
        # 单飞状态：仅在持有 _lock 时读写
        self._inflight: threading.Event | None = None
        self._inflight_error: BaseException | None = None

        # 首次加载为强约束：没有密钥集合则密钥环不可用
        self._locked_load(initial=True)

    # ------------------------------------------------------------------ #
    # 内部：单飞加载
    # ------------------------------------------------------------------ #
    def _locked_load(self, *, initial: bool) -> KeyringSnapshot:
        """在锁内执行一次真实拉取并替换快照。"""
        try:
            keys = self._source.load()
        except Exception as exc:  # 来源失败：首次直接抛，后续保留旧快照
            if initial or self._snapshot is None:
                raise TokenError(
                    "key source unavailable at initial load",
                    reason=TokenReasons.KEY_RELOAD_UNAVAILABLE,
                ) from exc
            raise TokenError(
                "key reload failed; serving previous key set",
                reason=TokenReasons.KEY_RELOAD_UNAVAILABLE,
            ) from exc

        index: dict[str, Key] = {}
        for key in keys:
            if key.kid in index:
                raise AuthError(
                    f"duplicate kid in key source: {key.kid}",
                    reason=TokenReasons.KEY_RELOAD_UNAVAILABLE,
                )
            index[key.kid] = key
        version = 0 if self._snapshot is None else self._snapshot.version + 1
        self._snapshot = KeyringSnapshot(keys=index, version=version)
        return self._snapshot

    def reload(self) -> KeyringSnapshot:
        """触发重载；并发调用合并为单次真实拉取（单飞）。

        由本线程实际执行拉取时，来源异常会向上抛出；等待其他线程拉取
        结果时同样感知其失败，但密钥环仍保留上一个良好快照。
        """
        with self._lock:
            if self._inflight is not None:
                event = self._inflight  # 他人正在拉取，等待同一结果
                leader = False
            else:
                event = threading.Event()
                self._inflight = event
                self._inflight_error = None
                leader = True

        if not leader:
            event.wait()
            with self._lock:
                err = self._inflight_error
            if err is not None:
                raise TokenError(
                    "concurrent key reload failed; previous key set retained",
                    reason=TokenReasons.KEY_RELOAD_UNAVAILABLE,
                ) from err
            assert self._snapshot is not None
            return self._snapshot

        # leader：执行真实拉取
        try:
            snap = self._locked_load(initial=False)
        except BaseException as exc:
            with self._lock:
                self._inflight_error = exc
                self._inflight = None
                event.set()
            raise
        else:
            with self._lock:
                self._inflight = None
                event.set()
            return snap

    # ------------------------------------------------------------------ #
    # 读路径
    # ------------------------------------------------------------------ #
    def current(self) -> KeyringSnapshot:
        """返回当前快照（构造时已完成首次加载，不会为空）。"""
        assert self._snapshot is not None
        return self._snapshot

    def latest_kid(self) -> str:
        """当前最新（首选签名）密钥标识。

        选取激活窗口起点 ``not_before`` 最大者；并列时取 kid 字典序最大，
        保证多副本/多次调用结果确定一致。
        """
        snap = self.current()
        if not snap.keys:
            raise AuthError(
                "keyring is empty", reason=TokenReasons.KEY_RELOAD_UNAVAILABLE
            )
        return max(snap.keys.values(), key=lambda k: (k.not_before, k.kid)).kid

    def signing_key(self) -> Key:
        """返回当前用于签发的密钥（必须严格 active，重叠宽限不用于签发）。"""
        snap = self.current()
        ts = self._clock()
        # 签发只使用严格处于激活窗口内的密钥，重叠宽限不用于签发
        pool = [k for k in snap.keys.values() if k.active_at(ts)]
        if not pool:
            raise AuthError(
                "no active signing key", reason=TokenReasons.KEY_RELOAD_UNAVAILABLE
            )
        return max(pool, key=lambda k: (k.not_before, k.kid))

    def verify_key(self, kid: str, *, at: float | None = None) -> Key:
        """按 kid 取可验签密钥。

        未知 kid 触发一次受控重载（单飞），重载后仍未知或已超出重叠
        窗口，则抛 :class:`TokenError` 风格的 unknown_kid。
        """
        ts = self._clock() if at is None else at
        snap = self.current()
        key = snap.get(kid)
        if key is None:
            # 受控重载：不直接判失败
            self.reload()
            snap = self.current()
            key = snap.get(kid)
            if key is None:
                raise TokenError(
                    f"unknown key id after controlled reload: {kid}",
                    reason=TokenReasons.UNKNOWN_KID,
                )
        if not key.usable_for_verify(ts, overlap_seconds=self._overlap):
            # 已知 kid，但已超出重叠宽限窗口
            raise TokenError(
                f"key id outside overlap window: {kid}",
                reason=TokenReasons.UNKNOWN_KID,
            )
        return key

    def constant_time_equal(self, a: bytes, b: bytes) -> bool:
        """恒定时间比较，避免签名比较侧信道。"""
        return hmac.compare_digest(a, b)
