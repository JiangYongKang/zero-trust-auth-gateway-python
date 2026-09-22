"""pytest 公共夹具：全部使用进程本地生成的密钥与策略，无外部依赖。"""

from __future__ import annotations

import logging
from typing import Iterator

import pytest

from ztauth.credentials import CredentialVault, InMemoryCredentialSource
from ztauth.engine import AuthGateway
from ztauth.keyring import Keyring, StaticKeySource, generate_key
from ztauth.logging_utils import configure_logging
from ztauth.policy import (
    HotReloadPolicyEngine,
    InMemoryPolicyStore,
    parse_policy,
)
from ztauth.tokens import issue_token


@pytest.fixture(autouse=True)
def _ztauth_logging(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """保证 ztauth 日志输出到控制台（满足可观测性要求）并可被 caplog 捕获。"""
    configure_logging(logging.INFO)
    caplog.set_level(logging.INFO, logger="ztauth")
    yield


@pytest.fixture()
def clock_state() -> dict:
    return {"now": 1000.0}


@pytest.fixture()
def clock(clock_state):
    return lambda: clock_state["now"]


def make_policy(version: int):
    return parse_policy(
        {
            "version": version,
            "rules": [
                {
                    "id": "allow-alice-db",
                    "effect": "allow",
                    "action": "read",
                    "resource": "db",
                    "principal_attr": "sub",
                    "principal_in": ["alice"],
                    "requires": ["dept"],
                },
                {
                    "id": "deny-carol-db",
                    "effect": "deny",
                    "action": "read",
                    "resource": "db",
                    "principal_attr": "sub",
                    "principal_in": ["carol"],
                },
            ],
        }
    )


@pytest.fixture()
def gateway(clock):
    """组装一个完整网关：本地密钥 + 本地策略 + 本地凭据。"""
    key = generate_key("k1")
    keyring = Keyring(StaticKeySource([key]), overlap_seconds=60.0, clock=clock)
    policy_store = InMemoryPolicyStore(make_policy(1))
    policies = HotReloadPolicyEngine(policy_store)
    cred_src = InMemoryCredentialSource()
    vault = CredentialVault(cred_src, clock=clock)
    vault.rotate("db", "LOCAL-SECRET-V1", read_scopes=["db:read"])
    gw = AuthGateway(keyring, policies, vault, clock=clock)
    # 把可替换的来源也暴露给测试，便于演练热更新/轮换
    gw._test_key_source = keyring._source  # type: ignore[attr-defined]
    gw._test_keyring = keyring  # type: ignore[attr-defined]
    gw._test_policy_store = policy_store  # type: ignore[attr-defined]
    gw._test_vault = vault  # type: ignore[attr-defined]
    return gw


@pytest.fixture()
def make_token(clock):
    """签发令牌的便捷夹具。"""

    def _make(gateway, sub="alice", scopes=("db:read",), attrs=None, ttl=100):
        attrs = {"dept": "eng"} if attrs is None else attrs
        tok, _ = issue_token(
            gateway._test_keyring,
            sub=sub,
            ttl_seconds=ttl,
            scopes=set(scopes),
            attributes=attrs,
            clock=clock,
        )
        return tok

    return _make
