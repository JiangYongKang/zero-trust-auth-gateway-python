"""零信任鉴权与凭据分发网关。

发布批次（release）能力见 ztauth.releases：把密钥 / 策略 / 凭据作为不可变
整体一起发布、回退与限期保留；未启用时 Gateway 仍走原有单项轮换 / 热更新路径。
"""
from .releases import (
    InMemoryReleaseSource,
    ReleaseBundle,
    ReleaseExpired,
    ReleaseManager,
    ReleaseNotFound,
    ReleasePayload,
)

__all__ = [
    "InMemoryReleaseSource",
    "ReleaseBundle",
    "ReleaseExpired",
    "ReleaseManager",
    "ReleaseNotFound",
    "ReleasePayload",
]
