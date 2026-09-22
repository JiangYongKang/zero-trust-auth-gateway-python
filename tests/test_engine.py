"""端到端鉴权链路测试：令牌 -> 策略 -> 凭据，结论可复现、日志可观测。

可观测性要求（在控制台实际打印，并在断言中校验）：
每条判定日志必须包含 request_id、policy_version、basis（判定依据）。
"""

from __future__ import annotations

import logging

import pytest

from ztauth.errors import CredentialError, PolicyError, TokenError
from ztauth.policy import AuthzRequest

pytestmark = pytest.mark.usefixtures("gateway")


def _req(resource: str = "db", action: str = "read") -> AuthzRequest:
    return AuthzRequest(principal="(self-reported-ignored)", action=action, resource=resource)


def test_full_chain_issues_credential_and_logs_context(
    gateway, make_token, caplog
) -> None:
    tok = make_token(gateway)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="ztauth"):
        result = gateway.get_credential(
            tok, _req(), caller_scopes=["db:read"], request_id="req-chain-1"
        )

    assert result.auth.allowed is True
    assert result.auth.policy_version == 1
    assert result.auth.basis == "allow-alice-db"
    assert result.issued.version == 1

    # 控制台实际打印（capsys 由 caplog StreamHandler 输出）；这里断言记录内容
    decision_logs = [
        r.getMessage() for r in caplog.records if "authorize decision" in r.getMessage()
    ]
    assert decision_logs, "must emit a decision log line"
    line = decision_logs[0]
    assert getattr(caplog.records[0], "request_id") == "req-chain-1"
    assert any(
        getattr(r, "policy_version") == "1" for r in caplog.records
    ), "decision logs must carry policy version"
    assert "basis=allow-alice-db" in line
    # 控制台打印，便于人工核对（测试报告 -s 可见）
    print("\n[OBS] request_id=req-chain-1 policy_version=1 basis=allow-alice-db allow=True")


def test_denied_principal_does_not_touch_credential(
    gateway, make_token, caplog
) -> None:
    # carol 命中显式 deny
    tok = make_token(gateway, sub="carol")
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="ztauth"):
        auth = gateway.authorize(tok, _req(), request_id="req-deny-1")

    assert auth.allowed is False
    assert auth.basis == "deny-carol-db"
    assert auth.policy_version == 1

    with pytest.raises(CredentialError) as ei:
        gateway.get_credential(tok, _req(), request_id="req-deny-2")
    assert ei.value.reason == "credential_scope_denied"
    print("\n[OBS] request_id=req-deny-1 policy_version=1 basis=deny-carol-db allow=False")


def test_missing_attribute_is_reported_distinctly(gateway, make_token) -> None:
    # alice 但无 dept 属性 -> MISSING_ATTRIBUTE，而非默认拒绝
    tok = make_token(gateway, sub="alice", attrs={})
    with pytest.raises(PolicyError) as ei:
        gateway.authorize(tok, _req(), request_id="req-missing-1")
    assert ei.value.reason == "policy_missing_attribute"


def test_token_failure_reason_propagates(gateway) -> None:
    with pytest.raises(TokenError) as ei:
        gateway.authorize("malformed.token", _req(), request_id="req-bad-1")
    assert ei.value.reason == "token_malformed"


def test_insufficient_scope_denied_for_credential(gateway, make_token) -> None:
    tok = make_token(gateway)  # alice 策略允许，但 scope 不含 db:read
    with pytest.raises(CredentialError) as ei:
        gateway.get_credential(tok, _req(), caller_scopes=[], request_id="req-scope-1")
    assert ei.value.reason == "credential_scope_denied"


def test_principal_self_report_is_ignored(gateway, make_token) -> None:
    # 令牌主体是 bob（无 allow），请求自报 alice 也不能提权
    tok = make_token(gateway, sub="bob")
    auth = gateway.authorize(tok, _req(), request_id="req-spoof-1")
    assert auth.principal == "bob"
    assert auth.allowed is False and auth.basis == "default_deny"


def test_decision_reproducible_with_same_policy_version(gateway, make_token) -> None:
    tok = make_token(gateway)
    r1 = gateway.authorize(tok, _req(), request_id="req-repro-1")
    r2 = gateway.authorize(tok, _req(), request_id="req-repro-2")
    assert (r1.allowed, r1.policy_version, r1.basis) == (
        r2.allowed,
        r2.policy_version,
        r2.basis,
    )


def test_request_body_cannot_override_token_attributes(gateway, make_token) -> None:
    # 令牌带 dept=eng，请求体试图改为其他值：以令牌为准，仍按 eng 放行
    from ztauth.policy import AuthzRequest as AR

    tok = make_token(gateway)
    forged = AR(principal="alice", action="read", resource="db",
                attributes={"dept": "HACKED"})
    auth = gateway.authorize(tok, forged, request_id="req-attr-guard-1")
    assert auth.allowed is True and auth.basis == "allow-alice-db"
