"""本地可运行的零信任网关演示装配。

启动：
    uv run uvicorn main:app --reload
所有密钥材料、策略与凭据均在本地构造/读取，不依赖任何外部服务。
修改 examples/policy.json 后调用 POST /v1/policies/reload 即可热生效。
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
    InMemoryCredentialVault,
    VersionState,
)
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import PolicyStore
from ztauth.sources import JsonPolicySource, MutableKeySource

_HERE = pathlib.Path(__file__).parent


def _build() -> Gateway:
    now = dt.datetime.now(dt.timezone.utc)
    # 本地生成的签名密钥材料（演示用固定字节；生产应由密钥源提供）
    keys = [
        SigningKey("k-old", os.urandom(32),
                   now - dt.timedelta(days=30), now + dt.timedelta(days=1),
                   "retiring"),
        SigningKey("k-current", os.urandom(32),
                   now - dt.timedelta(hours=1), now + dt.timedelta(days=30),
                   "active"),
    ]
    ring = KeyRing(MutableKeySource(keys, version=1))
    policies = PolicyStore(JsonPolicySource(_HERE / "examples" / "policy.json"))
    vault = InMemoryCredentialVault({
        "db-payments": Credential(
            name="db-payments",
            allowed_roles=("reader",),
            versions=(
                CredentialVersion(1, os.urandom(32), VersionState.CURRENT, None),
            ),
        ),
    })
    return Gateway(ring, policies, vault, AuditLogger())


gateway = _build()
app = create_app(gateway)
