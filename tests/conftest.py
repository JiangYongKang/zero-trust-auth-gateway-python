"""测试公共夹具：全部使用本地生成的密钥材料、策略与凭据。"""
from __future__ import annotations

import datetime as dt
import logging

import pytest

from ztauth.audit import AuditLogger
from ztauth.credentials import (
    Credential,
    CredentialVersion,
    InMemoryCredentialVault,
    VersionState,
)
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import Policy, Rule
from ztauth.policy import PolicyStore
from ztauth.sources import MutableKeySource

NOW = dt.datetime(2026, 9, 22, 0, 0, 0, tzinfo=dt.timezone.utc)


class FakeClock:
    """可手动推进的单调时钟：为回源节流的上限断言提供确定性时间。"""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class StaticPolicySource:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def load(self) -> Policy:
        return self.policy


@pytest.fixture(autouse=True)
def _audit_logging(caplog):
    caplog.set_level(logging.INFO, logger="ztauth.audit")


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def overlapping_keys(now):
    # 轮换重叠窗口：k1 行将退役，k2 已生效，两者在当前时刻均可用
    return [
        SigningKey(
            "k1", b"secret-one",
            now - dt.timedelta(days=30), now + dt.timedelta(days=1), "retiring",
        ),
        SigningKey(
            "k2", b"secret-two",
            now - dt.timedelta(hours=1), now + dt.timedelta(days=30), "active",
        ),
    ]


@pytest.fixture
def key_source(overlapping_keys):
    return MutableKeySource(overlapping_keys, version=1)


@pytest.fixture
def ring(key_source):
    return KeyRing(key_source)


@pytest.fixture
def vault(now):
    return InMemoryCredentialVault({
        "db-payments": Credential(
            name="db-payments",
            allowed_roles=("reader",),
            versions=(
                CredentialVersion(1, b"db-secret-v1", VersionState.CURRENT, None),
            ),
        ),
    })


@pytest.fixture
def base_policy():
    return Policy(
        version=1,
        rules=(
            Rule(
                "p1-allow-payments-reader", "allow", "read", "db-payments",
                require={"team": "payments"}, roles=("reader",),
            ),
            Rule(
                "p2-deny-contractor", "deny", "read", "db-payments",
                require={"employment": "contractor"}, roles=("reader",),
            ),
        ),
    )


@pytest.fixture
def policy_store(base_policy):
    return PolicyStore(StaticPolicySource(base_policy))


@pytest.fixture
def gateway_factory(ring, vault, caplog):
    def _factory(store: PolicyStore, *, revoked=None) -> Gateway:
        return Gateway(
            ring, store, vault, AuditLogger(),
            revoked=revoked, clock=lambda: NOW,
        )
    return _factory


@pytest.fixture
def gateway(gateway_factory, policy_store):
    return gateway_factory(policy_store)
