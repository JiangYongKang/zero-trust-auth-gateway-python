"""凭据读取与轮换测试。

覆盖：active/previous/retired 状态机、重叠期新旧版本语义、
最小权限（策略 + scope 双约束）、不存在版本/已失效版本拒绝原因可区分、
错误信息零泄露。
"""

from __future__ import annotations

import pytest

from ztauth.credentials import (
    ACTIVE,
    PREVIOUS,
    RETIRED,
    CredentialVault,
    InMemoryCredentialSource,
)
from ztauth.errors import CredentialError, CredentialReasons
from ztauth.policy import AuthzDecision

ALLOW = AuthzDecision("allow", 1, "r1", "explicit allow by rule r1", "r1")
DENY = AuthzDecision("deny", 1, "default_deny", "default deny", None)


@pytest.fixture()
def vault():
    src = InMemoryCredentialSource()
    v = CredentialVault(src, clock=lambda: 100.0)
    v.rotate("db", "SECRET-V1", read_scopes=["db:read"])
    v.rotate("db", "SECRET-V2")
    v.rotate("db", "SECRET-V3")
    return v


def _states(vault: CredentialVault, name: str = "db"):
    return {v.version: v.state for v in vault.current()[name].versions}


def test_rotation_state_machine_is_deterministic(vault) -> None:
    assert _states(vault) == {1: RETIRED, 2: PREVIOUS, 3: ACTIVE}
    assert vault.active_version("db") == 3


def test_default_read_returns_active_explicit_read_allows_previous(vault) -> None:
    cur = vault.read("db", ALLOW, caller_scopes=["db:read"])
    assert cur.version == 3 and cur.state == ACTIVE and cur.secret == "SECRET-V3"

    prev = vault.read("db", ALLOW, caller_scopes=["db:read"], version=2)
    assert prev.version == 2 and prev.state == PREVIOUS  # 重叠期显式可读


def test_reusing_retired_version_is_rejected_distinctly(vault) -> None:
    # v1 已被第三次轮换挤出重叠窗口
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=["db:read"], version=1)
    assert ei.value.reason == CredentialReasons.VERSION_RETIRED


def test_retire_ends_overlap_window(vault) -> None:
    vault.retire("db", 2)
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=["db:read"], version=2)
    assert ei.value.reason == CredentialReasons.VERSION_RETIRED


def test_unknown_credential_and_version_have_distinct_reasons(vault) -> None:
    with pytest.raises(CredentialError) as ei:
        vault.read("ghost", ALLOW, caller_scopes=["db:read"])
    assert ei.value.reason == CredentialReasons.NOT_FOUND
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=["db:read"], version=99)
    assert ei.value.reason == CredentialReasons.VERSION_NOT_FOUND


def test_least_privilege_requires_policy_allow_and_scopes(vault) -> None:
    with pytest.raises(CredentialError) as ei:
        vault.read("db", DENY, caller_scopes=["db:read"])
    assert ei.value.reason == CredentialReasons.SCOPE_DENIED
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=["other:read"])
    assert ei.value.reason == CredentialReasons.SCOPE_DENIED
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=[])
    assert ei.value.reason == CredentialReasons.SCOPE_DENIED


def test_secret_never_appears_in_error_messages(vault) -> None:
    for fn in (
        lambda: vault.read("db", ALLOW, caller_scopes=[], version=2),
        lambda: vault.read("db", ALLOW, caller_scopes=["db:read"], version=1),
        lambda: vault.read("db", ALLOW, caller_scopes=["db:read"], version=99),
    ):
        with pytest.raises(CredentialError) as ei:
            fn()
        assert "SECRET" not in str(ei.value)
        assert "SECRET" not in ei.value.message


def test_validity_window_is_enforced(vault) -> None:
    # 新版本带较短有效期，过期后默认读取（active 但超窗）被拒
    vault.rotate("db", "SECRET-V4", not_after=150.0)
    assert vault.read("db", ALLOW, caller_scopes=["db:read"]).version == 4
    vault._clock = lambda: 200.0
    with pytest.raises(CredentialError) as ei:
        vault.read("db", ALLOW, caller_scopes=["db:read"])
    assert ei.value.reason == CredentialReasons.NOT_READABLE
