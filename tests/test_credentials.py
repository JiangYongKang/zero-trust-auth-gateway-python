"""场景三：凭据最小权限、版本引用、轮换重叠期语义、密钥不入日志。"""
from __future__ import annotations

import datetime as dt
import logging

import pytest

from ztauth.credentials import (
    Credential,
    CredentialVersion,
    InMemoryCredentialVault,
    VersionState,
    read_credential,
)
from ztauth.errors import AuthError, DenyReason
from ztauth.gateway import Gateway
from ztauth.tokens import TokenIssuer


def _mk(now):
    return InMemoryCredentialVault({
        "db": Credential("db", ("reader",), (
            CredentialVersion(1, b"db-secret-v1", VersionState.CURRENT, None),
        )),
        "temp": Credential("temp", ("reader",), (
            CredentialVersion(1, b"temp-v1", VersionState.CURRENT,
                              now + dt.timedelta(hours=1)),
        )),
    })


def test_read_current_and_forbidden(now):
    store = _mk(now)
    issued = read_credential(store, "db", roles=("reader",))
    assert issued.version == 1 and issued.secret == b"db-secret-v1"
    with pytest.raises(AuthError) as ei:
        read_credential(store, "db", roles=("writer",))
    assert ei.value.reason is DenyReason.CREDENTIAL_FORBIDDEN


def test_unknown_and_retired_versions_distinguishable(now):
    store = _mk(now)
    with pytest.raises(AuthError) as ei:
        read_credential(store, "db", roles=("reader",), version=99)
    assert ei.value.reason is DenyReason.CREDENTIAL_VERSION_NOT_FOUND
    store.rotate("db", b"db-secret-v2")
    # 重叠期：v1=previous 可显式读，v2=current
    assert read_credential(store, "db", roles=("reader",)).version == 2
    assert read_credential(store, "db", roles=("reader",), version=1).version == 1
    # 再次轮换：v1 立即 retired，v2 进入 previous
    store.rotate("db", b"db-secret-v3")
    with pytest.raises(AuthError) as ei:
        read_credential(store, "db", roles=("reader",), version=1)
    assert ei.value.reason is DenyReason.CREDENTIAL_VERSION_RETIRED
    assert read_credential(store, "db", roles=("reader",), version=2).version == 2
    # 结束重叠期：v2 也 retired
    store.retire_previous("db")
    with pytest.raises(AuthError) as ei:
        read_credential(store, "db", roles=("reader",), version=2)
    assert ei.value.reason is DenyReason.CREDENTIAL_VERSION_RETIRED
    with pytest.raises(AuthError) as ei:
        read_credential(store, "missing", roles=("reader",))
    assert ei.value.reason is DenyReason.CREDENTIAL_NOT_FOUND


def test_expired_current_version_rejected(now):
    store = _mk(now)
    future = now + dt.timedelta(hours=2)
    with pytest.raises(AuthError) as ei:
        read_credential(store, "temp", roles=("reader",), now=future)
    assert ei.value.reason is DenyReason.CREDENTIAL_VERSION_RETIRED
    assert "db-secret" not in (ei.value.detail or "")  # 错误不含内容


def test_gateway_credential_flow_and_no_secret_in_logs(
    gateway, ring, caplog, now
):
    token = TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"team": "payments"}, now=now,
    )
    # 注意 gateway 夹具的凭据名是 db-payments
    result = gateway.authorize("rq-cred", token, "read", "db-payments", now=now)
    assert result.credential is not None
    assert result.credential.version == 1
    assert result.credential.secret == b"db-secret-v1"

    # 全部审计/日志文本中不得出现凭据明文或令牌字符串
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert "db-secret-v1" not in blob
    assert token not in blob
    # 必须记录请求标识、策略版本与判定依据
    assert "rq-cred" in blob and "policy v1" in blob


def test_gateway_credential_rotation_semantics(
    gateway_factory, ring, policy_store, vault, now
):
    gw = gateway_factory(policy_store)
    token = TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"team": "payments"}, now=now,
    )
    def auth(version=None):
        return gw.authorize("rq", token, "read", "db-payments",
                            credential_version=version, now=now)

    assert auth().credential.version == 1
    assert auth(version=1).credential.version == 1  # 重叠前显式引用当前版本
    vault.rotate("db-payments", b"db-secret-v2")
    assert auth().credential.version == 2            # 默认取新
    assert auth(version=1).credential.version == 1   # 重叠期旧版本仍可用
    vault.rotate("db-payments", b"db-secret-v3")
    with pytest.raises(AuthError) as ei:
        auth(version=1)
    assert ei.value.reason is DenyReason.CREDENTIAL_VERSION_RETIRED
    assert auth(version=2).credential.version == 2
