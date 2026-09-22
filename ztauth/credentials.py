"""版本化凭据的读取与轮换：最小权限、确定的重叠期语义、零泄露。

安全约定：

* 凭据明文（``secret``）永不出现在日志、异常消息或返回的描述字段中；
  仅在 :class:`IssuedCredential` 中一次性交付给已授权调用方。
* 版本状态：``active``（当前）、``previous``（重叠期内仍可按显式版本读取）、
  ``retired``（已失效，再引用即拒绝 VERSION_RETIRED）。
* 读取必须同时通过策略授权（scope/动作）与凭据自身的 read scope 约束。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Protocol

from ztauth.policy import AuthzDecision


class VersionState(str, Enum):
    ACTIVE = "active"
    PREVIOUS = "previous"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class CredentialVersion:
    """凭据的一个版本（secret 仅在授权读取时交付）。"""

    name: str
    version: int
    secret: str
    state: VersionState
    not_before: float = 0.0
    not_after: float = float("inf")
    read_scopes: frozenset[str] = frozenset()   # 读取所需最小权限


@dataclass(frozen=True, slots=True)
class CredentialSet:
    """一个具名凭据的全部版本。"""

    name: str
    versions: tuple[CredentialVersion, ...] = ()
    rotate_interval: float = 0.0


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    """一次性交付给调用方的凭据（禁止记录其 secret）。"""

    name: str
    version: int
    secret: str
    expires_at: float
    state: VersionState


class CredentialSource(Protocol):
    """凭据材料来源（本地文件/内存生成）。"""

    def load(self) -> dict[str, CredentialSet]:
        ...


class CredentialVault:
    """并发安全的版本化凭据保险库，支持热更新与轮换。"""

    def __init__(
        self,
        source: CredentialSource,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        raise NotImplementedError

    def current(self) -> dict[str, CredentialSet]:
        raise NotImplementedError

    def reload(self) -> dict[str, CredentialSet]:
        """并发调用合并为单次拉取（单飞），重载期间旧快照保持可用。"""
        raise NotImplementedError

    def active_version(self, name: str) -> int:
        """返回当前 active 版本号；凭据不存在抛 NOT_FOUND。"""
        raise NotImplementedError

    def read(
        self,
        name: str,
        decision: AuthzDecision,
        *,
        caller_scopes: Iterable[str] = (),
        version: int | None = None,
        for_rotation: bool = False,
    ) -> IssuedCredential:
        """按最小权限读取凭据。

        拒绝原因（:class:`CredentialReasons`）：
        NOT_FOUND / VERSION_NOT_FOUND / VERSION_RETIRED /
        SCOPE_DENIED / NOT_READABLE / NOT_ROTATABLE。
        """
        raise NotImplementedError

    def rotate(self, name: str, new_secret: str) -> CredentialSet:
        """轮换：旧 active → previous（重叠窗口），新版本 → active。"""
        raise NotImplementedError

    def retire(self, name: str, version: int) -> CredentialSet:
        """将重叠期版本标记为 retired（重叠窗口结束）。"""
        raise NotImplementedError
