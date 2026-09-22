"""签名密钥环：多版本密钥、轮换重叠窗口与受控重载。

设计要点（实现阶段填充）：

* 每个密钥有 ``kid`` 与激活/停用时间；轮换期间新旧密钥在确定的
  重叠窗口内同时可用于验签。
* 遇到未知 ``kid`` 时触发"单飞"重载：并发请求只允许一次拉取，
  其余请求等待同一结果，重载期间旧密钥集合保持可用，不出现短暂失效。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol


@dataclass(frozen=True, slots=True)
class Key:
    """一个验签密钥（仅含公开校验材料，对称密钥即共享秘密）。"""

    kid: str
    secret: bytes
    not_before: float = 0.0
    not_after: float = float("inf")

    def active_at(self, ts: float | None = None) -> bool:
        """密钥在给定时间点是否处于激活窗口内。"""
        raise NotImplementedError

    def usable_for_verify(self, ts: float | None = None) -> bool:
        """是否可用于验签（实现阶段定义与 active_at 的差异）。"""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class KeyringSnapshot:
    """密钥集合的不可变快照，读路径无锁共享。"""

    keys: dict[str, Key] = field(default_factory=dict)
    version: int = 0

    def get(self, kid: str) -> Key | None:
        raise NotImplementedError


class KeySource(Protocol):
    """密钥材料来源（本地生成或本地文件，禁止远程依赖）。"""

    def load(self) -> list[Key]:
        """返回当前应保留的密钥集合。"""
        ...


class Keyring:
    """并发安全、支持重叠轮换与单飞重载的密钥环。"""

    def __init__(
        self,
        source: KeySource,
        *,
        overlap_seconds: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        raise NotImplementedError

    def current(self) -> KeyringSnapshot:
        """返回当前快照（必要时阻塞等待首次加载）。"""
        raise NotImplementedError

    def verify_key(self, kid: str) -> Key:
        """按 kid 取可用密钥；未知 kid 触发一次受控重载。"""
        raise NotImplementedError

    def reload(self) -> KeyringSnapshot:
        """强制重载；并发调用合并为单次拉取（单飞）。"""
        raise NotImplementedError

    def latest_kid(self) -> str:
        """当前最新（首选签名）密钥标识。"""
        raise NotImplementedError
