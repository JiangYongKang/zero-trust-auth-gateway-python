"""带版本与有效期的凭据：最小权限读取 + 确定语义的轮换。

轮换语义（重叠窗口）：
- rotate 后：新版本=CURRENT，旧 CURRENT 降级为 PREVIOUS（重叠期内仍可显式引用），
  更早的 PREVIOUS 变为 RETIRED（任何引用都拒绝）。
- retire_previous 结束重叠期：PREVIOUS -> RETIRED。
读取解析：
- version=None：仅返回 CURRENT；CURRENT 若已到 not_after 则判定失效。
- version=N 显式引用：PREVIOUS 在重叠期且未到 not_after 可读取；
  RETIRED 一律拒绝；不存在的版本号拒绝。两个原因彼此可区分。
凭据明文只出现在 IssuedCredential.secret 中，绝不进入日志或异常文本。
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import threading
from typing import Protocol

from .errors import AuthError, DenyReason


class VersionState(str, enum.Enum):
    CURRENT = "current"
    PREVIOUS = "previous"   # 轮换重叠期：仍可读取
    RETIRED = "retired"     # 已失效：引用即拒绝


@dataclasses.dataclass(frozen=True)
class CredentialVersion:
    version: int
    secret: bytes
    state: VersionState
    not_after: dt.datetime | None  # UTC, exclusive；None 表示无过期时间


@dataclasses.dataclass(frozen=True)
class Credential:
    name: str
    allowed_roles: tuple[str, ...]  # 最小权限：仅这些角色可读取
    versions: tuple[CredentialVersion, ...]


@dataclasses.dataclass(frozen=True)
class IssuedCredential:
    name: str
    version: int
    secret: bytes
    not_after: dt.datetime | None


class CredentialStore(Protocol):
    def load_all(self) -> dict[str, Credential]:
        ...


def _fresh(v: CredentialVersion, now: dt.datetime) -> bool:
    return v.not_after is None or now < v.not_after


class FrozenCredentialStore:
    """发布批次内的不可变凭据快照：只读 load_all，不支持轮换。

    它满足 read_credential 所需的 CredentialStore 协议，使一个请求全程读取
    固定批次中的凭据版本集合，不受并发轮换影响。
    """

    def __init__(self, snapshot: dict[str, Credential]) -> None:
        self._snapshot = dict(snapshot)

    def load_all(self) -> dict[str, Credential]:
        # 返回浅拷贝，Credential 本身是不可变对象，可安全共享
        return dict(self._snapshot)


class InMemoryCredentialVault:
    """线程安全的本地凭据库快照，供测试与本地验证使用。"""

    def __init__(self, initial: dict[str, Credential] | None = None) -> None:
        self._lock = threading.Lock()
        self._creds: dict[str, Credential] = dict(initial or {})

    def load_all(self) -> dict[str, Credential]:
        with self._lock:
            return dict(self._creds)

    def snapshot(self) -> dict[str, Credential]:
        return self.load_all()

    def rotate(
        self,
        name: str,
        secret: bytes,
        *,
        now: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
    ) -> int:
        """轮换到新版本，返回新版本号；旧版本进入 PREVIOUS 重叠期。"""
        with self._lock:
            cred = self._creds.get(name)
            if cred is None:
                raise KeyError(name)
            new_versions: list[CredentialVersion] = []
            next_no = 1
            for v in cred.versions:
                if v.state == VersionState.CURRENT:
                    new_versions.append(dataclasses.replace(v, state=VersionState.PREVIOUS))
                elif v.state == VersionState.PREVIOUS:
                    new_versions.append(dataclasses.replace(v, state=VersionState.RETIRED))
                else:
                    new_versions.append(v)
                next_no = max(next_no, v.version + 1)
            new_versions.append(
                CredentialVersion(next_no, secret, VersionState.CURRENT, not_after)
            )
            self._creds[name] = dataclasses.replace(cred, versions=tuple(new_versions))
            return next_no

    def retire_previous(self, name: str) -> None:
        """结束重叠期：PREVIOUS -> RETIRED。"""
        with self._lock:
            cred = self._creds[name]
            self._creds[name] = dataclasses.replace(
                cred,
                versions=tuple(
                    dataclasses.replace(v, state=VersionState.RETIRED)
                    if v.state == VersionState.PREVIOUS else v
                    for v in cred.versions
                ),
            )


def read_credential(
    store: CredentialStore,
    name: str,
    *,
    roles: tuple[str, ...],
    version: int | None = None,
    now: dt.datetime | None = None,
) -> IssuedCredential:
    now = now or dt.datetime.now(dt.timezone.utc)
    cred = store.load_all().get(name)
    if cred is None:
        raise AuthError(DenyReason.CREDENTIAL_NOT_FOUND, f"credential={name}")
    # 最小权限：先于版本判定，避免向无权方暴露版本存在性
    if not set(roles) & set(cred.allowed_roles):
        raise AuthError(DenyReason.CREDENTIAL_FORBIDDEN, f"credential={name}")

    if version is None:
        target = next((v for v in cred.versions if v.state == VersionState.CURRENT), None)
        if target is None:
            raise AuthError(DenyReason.CREDENTIAL_VERSION_NOT_FOUND, "no current version")
    else:
        target = next((v for v in cred.versions if v.version == version), None)
        if target is None:
            raise AuthError(
                DenyReason.CREDENTIAL_VERSION_NOT_FOUND,
                f"credential={name} version={version}",
            )
        if target.state == VersionState.RETIRED:
            raise AuthError(
                DenyReason.CREDENTIAL_VERSION_RETIRED,
                f"credential={name} version={version}",
            )
    if not _fresh(target, now):
        # 过期的当前/重叠版本按"已失效版本"拒绝
        if target.state == VersionState.RETIRED or version is not None:
            raise AuthError(
                DenyReason.CREDENTIAL_VERSION_RETIRED,
                f"credential={name} version={target.version} expired",
            )
        raise AuthError(
            DenyReason.CREDENTIAL_VERSION_RETIRED,
            f"credential={name} current expired",
        )
    return IssuedCredential(
        name=name,
        version=target.version,
        secret=target.secret,
        not_after=target.not_after,
    )
