"""本地可运行的零信任网关演示装配（发布批次模式）。

启动：
    uv run uvicorn main:app --reload

所有密钥材料、策略与凭据均在本地构造/读取，不依赖任何外部服务。
初始配置作为发布标识 1 的批次加载；之后通过
    POST /v1/releases/publish   发布源中的新整批配置
    POST /v1/releases/rollback  {"release_id": N}  回退到保留期内的批次
完成"同批生效、整批回退"。修改 examples/policy.json 后再 publish 即可。
未配置发布批次的原有单项路径仍可直接使用 Gateway(ring, policies, vault)。
"""
from __future__ import annotations

import datetime as dt
import os
import pathlib

from ztauth.api import create_app
from ztauth.audit import AuditLogger
from ztauth.credentials import (
    Credential,
    CredentialVersion,
    VersionState,
)
from ztauth.gateway import Gateway
from ztauth.keys import SigningKey
from ztauth.releases import ReleaseContent, ReleaseManager
from ztauth.sources import JsonPolicySource, MutableReleaseSource

_HERE = pathlib.Path(__file__).parent


def _initial_content(now: dt.datetime) -> ReleaseContent:
    keys = (
        SigningKey("k-old", os.urandom(32),
                   now - dt.timedelta(days=30), now + dt.timedelta(days=1),
                   "retiring"),
        SigningKey("k-current", os.urandom(32),
                   now - dt.timedelta(hours=1), now + dt.timedelta(days=30),
                   "active"),
    )
    policy = JsonPolicySource(_HERE / "examples" / "policy.json").load()
    credentials = {
        "db-payments": Credential(
            name="db-payments",
            allowed_roles=("reader",),
            versions=(
                CredentialVersion(1, os.urandom(32), VersionState.CURRENT, None),
            ),
        ),
    }
    return ReleaseContent(keys=keys, policy=policy,
                          credentials=credentials, keys_version=1)


def _build() -> tuple[Gateway, MutableReleaseSource]:
    now = dt.datetime.now(dt.timezone.utc)
    source = MutableReleaseSource(_initial_content(now))
    # reload_min_interval 默认 1s：未知 kid 冲击下真实回源 <= 1 + 经过时间/间隔
    manager = ReleaseManager(source, max_retained=8, reload_min_interval=1.0)
    return Gateway(released=manager, audit=AuditLogger()), source


gateway, release_source = _build()
app = create_app(gateway)
