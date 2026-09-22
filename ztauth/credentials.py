"""版本化凭据的读取与轮换：最小权限、确定的重叠期语义、零泄露。

版本状态机
==========

``active`` -> ``previous`` -> ``retired``

* **轮换** :meth:`CredentialVault.rotate`：新版本成为 ``active``；
  原 ``active`` 变为 ``previous``（重叠窗口）；原 ``previous``（若存在）
  立即变为 ``retired``。任意时刻一个具名凭据至多有一个 active 与一个
  previous，语义确定无歧义。
* **重叠期** : ``previous`` 版本允许通过 *显式版本号* 读取，便于正在
  进行的调用方完成收尾；不带版本号的读取始终解析为当前 ``active``。
* **失效** :meth:`retire` 或被后续轮换挤出重叠窗口的版本为
  ``retired``，再引用（即使显式指定版本号）一律拒绝
  ``VERSION_RETIRED``，杜绝已失效版本被重复使用。

最小权限
========
读取必须同时满足：

1. 策略链路已给出 ``allow`` 判定（:class:`AuthzDecision`）；
2. 调用方 scope 集合覆盖该版本 ``read_scopes`` 的全部要求
   （少一个即 ``SCOPE_DENIED``）；
3. 版本处于可读取状态且在 ``[not_before, not_after)`` 有效期内。

零泄露
======
凭据明文只出现在 :class:`IssuedCredential.secret` 中一次性交付；
所有异常消息、日志字段、版本描述均只含凭据 *名称* 与 *版本号*。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from ztauth.errors import CredentialError, CredentialReasons
from ztauth.policy import AuthzDecision


@dataclass(frozen=True, slots=True)
class CredentialVersion:
    """凭据的一个版本。"""

    name: str
    version: int
    secret: str
    state: str  # VersionState 的值
    not_before: float = 0.0
    not_after: float = float("inf")
    read_scopes: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class CredentialSet:
    """一个具名凭据的全部版本。"""

    name: str
    versions: tuple[CredentialVersion, ...] = ()
    rotate_interval: float = 0.0

    def by_state(self, state: str) -> CredentialVersion | None:
        for v in self.versions:
            if v.state == state:
                return v
        return None


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    """一次性交付给调用方的凭据。**禁止记录其 secret**。"""

    name: str
    version: int
    secret: str
    expires_at: float
    state: str


ACTIVE = "active"
PREVIOUS = "previous"
RETIRED = "retired"


class CredentialSource(Protocol):
    """凭据材料来源（本地文件/内存生成）。"""

    def load(self) -> dict[str, CredentialSet]:
        ...


class InMemoryCredentialSource:
    """内存凭据来源：测试与本地演示用，可原子替换并模拟轮换。"""

    def __init__(self, sets: dict[str, CredentialSet] | None = None) -> None:
        self._sets: dict[str, CredentialSet] = dict(sets or {})
        self._rev = 0
        self._lock = threading.Lock()

    def replace_all(self, sets: dict[str, CredentialSet]) -> None:
        with self._lock:
            self._sets = dict(sets)
            self._rev += 1

    def upsert(self, cset: CredentialSet) -> None:
        with self._lock:
            self._sets[cset.name] = cset
            self._rev += 1

    def fingerprint(self) -> str:
        with self._lock:
            return f"rev={self._rev};sets={len(self._sets)}"

    def load(self) -> dict[str, CredentialSet]:
        with self._lock:
            return {k: v for k, v in self._sets.items()}


def make_version(
    name: str,
    version: int,
    secret: str,
    *,
    state: str = ACTIVE,
    not_before: float = 0.0,
    not_after: float = float("inf"),
    read_scopes: Iterable[str] = (),
) -> CredentialVersion:
    """构造一个凭据版本（本地生成材料，测试便捷函数）。"""
    return CredentialVersion(
        name=name,
        version=version,
        secret=secret,
        state=state,
        not_before=not_before,
        not_after=not_after,
        read_scopes=frozenset(read_scopes),
    )


def _ce(reason: str, message: str) -> CredentialError:
    # message 中只允许出现名称/版本号，调用方需自行遵守
    return CredentialError(message, reason=reason)


class CredentialVault:
    """并发安全的版本化凭据保险库，支持热更新与轮换。"""

    def __init__(
        self,
        source: CredentialSource,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._source = source
        self._clock = clock
        self._lock = threading.Lock()
        self._sets: dict[str, CredentialSet] = {}
        self._inflight: threading.Event | None = None
        self._inflight_error: BaseException | None = None
        # 首次强加载
        self._locked_load(initial=True)

    # ------------------------------------------------------------------ #
    # 加载（单飞）
    # ------------------------------------------------------------------ #
    def _locked_load(self, *, initial: bool) -> dict[str, CredentialSet]:
        try:
            sets = self._source.load()
        except Exception as exc:
            if initial:
                raise _ce(
                    CredentialReasons.RELOAD_UNAVAILABLE,
                    "credential source unavailable at initial load",
                ) from exc
            raise _ce(
                CredentialReasons.RELOAD_UNAVAILABLE,
                "credential reload failed; previous snapshot retained",
            ) from exc
        self._sets = dict(sets)
        return self._sets

    def reload(self) -> dict[str, CredentialSet]:
        """触发重载；并发调用合并为单次拉取（单飞），期间旧快照可用。"""
        with self._lock:
            if self._inflight is not None:
                event, leader = self._inflight, False
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
                raise _ce(
                    CredentialReasons.RELOAD_UNAVAILABLE,
                    "concurrent credential reload failed; snapshot retained",
                ) from err
            return self._sets

        try:
            self._locked_load(initial=False)
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
            return self._sets

    def current(self) -> dict[str, CredentialSet]:
        return self._sets

    # ------------------------------------------------------------------ #
    # 读取
    # ------------------------------------------------------------------ #
    def _get_set(self, name: str) -> CredentialSet:
        cset = self._sets.get(name)
        if cset is None:
            raise _ce(CredentialReasons.NOT_FOUND, f"credential not found: {name}")
        return cset

    def active_version(self, name: str) -> int:
        cset = self._get_set(name)
        active = cset.by_state(ACTIVE)
        if active is None:  # 结构异常：凭据存在但无 active 版本
            raise _ce(CredentialReasons.NOT_FOUND, f"no active version: {name}")
        return active.version

    @staticmethod
    def _check_policy(decision: AuthzDecision) -> None:
        if decision.decision != "allow":
            raise _ce(
                CredentialReasons.SCOPE_DENIED,
                f"policy denied this access (basis={decision.basis})",
            )

    @staticmethod
    def _check_scopes(ver: CredentialVersion, caller: frozenset[str]) -> None:
        missing = ver.read_scopes - caller
        if missing:
            # 不回显缺失的具体 scope 名称以外信息；scope 非敏感但保持克制
            raise _ce(
                CredentialReasons.SCOPE_DENIED,
                f"caller lacks required scopes for {ver.name} v{ver.version}",
            )

    def read(
        self,
        name: str,
        decision: AuthzDecision,
        *,
        caller_scopes: Iterable[str] = (),
        version: int | None = None,
        for_rotation: bool = False,
    ) -> IssuedCredential:
        """按最小权限读取凭据；任一不满足即以可区分原因拒绝。"""
        # 1) 策略必须明确允许
        self._check_policy(decision)

        cset = self._get_set(name)
        now = self._clock()

        # 2) 解析目标版本：缺省为 active；显式版本必须存在
        if version is None:
            target = cset.by_state(ACTIVE)
            if target is None:
                raise _ce(CredentialReasons.NOT_FOUND, f"no active version: {name}")
        else:
            target = next((v for v in cset.versions if v.version == version), None)
            if target is None:
                raise _ce(
                    CredentialReasons.VERSION_NOT_FOUND,
                    f"version not found: {name} v{version}",
                )

        # 3) 状态校验：retired 永不放行（重复使用已失效版本）
        if target.state == RETIRED:
            raise _ce(
                CredentialReasons.VERSION_RETIRED,
                f"version retired and must not be reused: {name} v{target.version}",
            )

        # 4) 非轮换场景：previous 仅允许显式版本读取（上面 version is not
        #    None 的路径）；缺省读取已固定为 active，因此这里只需在
        #    "默认解析"与"previous"组合时拒绝（理论不可达，显式守护）
        if target.state == PREVIOUS and version is None and not for_rotation:
            raise _ce(
                CredentialReasons.NOT_READABLE,
                f"previous version requires explicit version: {name}",
            )

        # 5) 有效期窗口
        if not (target.not_before <= now < target.not_after):
            if target.state == PREVIOUS:
                raise _ce(
                    CredentialReasons.VERSION_RETIRED,
                    f"previous version outside validity window: {name} v{target.version}",
                )
            raise _ce(
                CredentialReasons.NOT_READABLE,
                f"version outside validity window: {name} v{target.version}",
            )

        # 6) 最小权限 scope
        self._check_scopes(target, frozenset(caller_scopes))

        return IssuedCredential(
            name=name,
            version=target.version,
            secret=target.secret,
            expires_at=target.not_after,
            state=target.state,
        )

    # ------------------------------------------------------------------ #
    # 轮换 / 失效
    # ------------------------------------------------------------------ #
    def _mutate(self, name: str, new_set: CredentialSet) -> CredentialSet:
        with self._lock:
            self._sets[name] = new_set
        return new_set

    def rotate(
        self,
        name: str,
        new_secret: str,
        *,
        not_after: float = float("inf"),
        read_scopes: Iterable[str] | None = None,
    ) -> CredentialSet:
        """轮换凭据。

        新版本号 = 现有最大版本号 + 1；旧 active -> previous；
        旧 previous -> retired（离开重叠窗口）。不存在的凭据以 v1 建立。
        """
        with self._lock:
            cset = self._sets.get(name)
            if cset is None:
                v1 = make_version(
                    name, 1, new_secret, state=ACTIVE,
                    not_after=not_after,
                    read_scopes=() if read_scopes is None else read_scopes,
                )
                created = CredentialSet(name=name, versions=(v1,))
                self._sets[name] = created
                return created

            transitioned: list[CredentialVersion] = []
            max_version = 0
            scopes: frozenset[str] = frozenset()
            for v in cset.versions:
                max_version = max(max_version, v.version)
                if v.state == ACTIVE:
                    scopes = v.read_scopes
                    transitioned.append(
                        CredentialVersion(
                            name=v.name, version=v.version, secret=v.secret,
                            state=PREVIOUS, not_before=v.not_before,
                            not_after=v.not_after, read_scopes=v.read_scopes,
                        )
                    )
                elif v.state == PREVIOUS:
                    transitioned.append(
                        CredentialVersion(
                            name=v.name, version=v.version, secret=v.secret,
                            state=RETIRED, not_before=v.not_before,
                            not_after=v.not_after, read_scopes=v.read_scopes,
                        )
                    )
                else:
                    transitioned.append(v)

            new_ver = make_version(
                name,
                max_version + 1,
                new_secret,
                state=ACTIVE,
                not_after=not_after,
                read_scopes=scopes if read_scopes is None else read_scopes,
            )
            # 排序仅用于展示稳定：版本号升序
            transitioned.append(new_ver)
            transitioned.sort(key=lambda v: v.version)
            new_set = CredentialSet(
                name=name, versions=tuple(transitioned),
                rotate_interval=cset.rotate_interval,
            )
            self._sets[name] = new_set
            return new_set

    def retire(self, name: str, version: int) -> CredentialSet:
        """显式结束重叠窗口：将指定 previous 版本标记为 retired。"""
        with self._lock:
            cset = self._get_set(name)
            target = next((v for v in cset.versions if v.version == version), None)
            if target is None:
                raise _ce(
                    CredentialReasons.VERSION_NOT_FOUND,
                    f"version not found: {name} v{version}",
                )
            new_versions = tuple(
                CredentialVersion(
                    name=v.name, version=v.version, secret=v.secret, state=RETIRED,
                    not_before=v.not_before, not_after=v.not_after,
                    read_scopes=v.read_scopes,
                )
                if v.version == version
                else v
                for v in cset.versions
            )
            new_set = CredentialSet(
                name=name, versions=new_versions, rotate_interval=cset.rotate_interval
            )
            self._sets[name] = new_set
            return new_set
