"""可区分的鉴权/授权/凭据错误原因。"""
from __future__ import annotations

import enum


class DenyReason(str, enum.Enum):
    """令牌、授权、凭据三类拒绝原因，取值可直接用于日志与响应。"""

    # ---- 令牌 (authn) ----
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_UNKNOWN_KID = "token_unknown_kid"
    TOKEN_SIGNATURE_MISMATCH = "token_signature_mismatch"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_KEY_RELOAD_UNAVAILABLE = "token_key_reload_unavailable"

    # ---- 授权 (authz) ----
    POLICY_DENY = "policy_deny"
    POLICY_MISSING_ATTRIBUTE = "policy_missing_attribute"

    # ---- 凭据 ----
    CREDENTIAL_NOT_FOUND = "credential_not_found"
    CREDENTIAL_VERSION_NOT_FOUND = "credential_version_not_found"
    CREDENTIAL_VERSION_RETIRED = "credential_version_retired"
    CREDENTIAL_FORBIDDEN = "credential_forbidden"


class AuthError(Exception):
    """带可区分原因的鉴权失败；不携带凭据内容。"""

    def __init__(self, reason: DenyReason, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(detail or reason.value)
