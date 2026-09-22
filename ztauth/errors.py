"""错误类型与可区分的拒绝原因。

所有鉴权/授权/凭据相关异常都继承自 :class:`AuthError`，
并通过 ``reason`` 字段携带机器可区分的稳定原因码，
错误信息中绝不包含密钥或凭据明文。
"""

from __future__ import annotations


class AuthError(Exception):
    """鉴权链路错误基类。

    :param reason: 稳定的机器可读原因码
    :param message: 面向调用方的安全描述（不得包含敏感材料）
    """

    reason: str = "internal_error"

    def __init__(self, message: str = "", *, reason: str | None = None) -> None:
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason
        self.message = message or self.reason


class TokenError(AuthError):
    """令牌校验失败。"""

    reason = "token_invalid"


class TokenReasons:
    """令牌校验失败的细分原因码。"""

    MALFORMED = "token_malformed"            # 令牌结构无法解析
    UNKNOWN_KID = "token_unknown_kid"        # 未知密钥标识（触发受控重载）
    SIGNATURE_MISMATCH = "token_signature_mismatch"
    EXPIRED = "token_expired"
    REVOKED = "token_revoked"
    NOT_YET_VALID = "token_not_yet_valid"
    KEY_RELOAD_UNAVAILABLE = "key_reload_unavailable"


class PolicyError(AuthError):
    """策略加载或判定错误。"""

    reason = "policy_error"


class PolicyReasons:
    MISSING_ATTRIBUTE = "policy_missing_attribute"  # 缺少必要属性（区别于拒绝）
    NO_POLICY_LOADED = "policy_not_loaded"
    INVALID_POLICY = "policy_invalid"
    POLICY_RELOAD_UNAVAILABLE = "policy_reload_unavailable"


class CredentialError(AuthError):
    """凭据读取/轮换失败。"""

    reason = "credential_error"


class CredentialReasons:
    NOT_FOUND = "credential_not_found"
    VERSION_NOT_FOUND = "credential_version_not_found"
    VERSION_RETIRED = "credential_version_retired"   # 重复使用已失效版本
    SCOPE_DENIED = "credential_scope_denied"         # 最小权限越权
    NOT_READABLE = "credential_not_readable"
    NOT_ROTATABLE = "credential_not_rotatable"
    RELOAD_UNAVAILABLE = "credential_reload_unavailable"
