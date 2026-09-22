"""鉴权编排：令牌校验 -> 策略判定 -> 凭据读取。

该门面负责把三个独立子系统组合成一条链路，并保证：

* **结论可解释、可复现**：:class:`AuthResult` 记录请求标识、主体、
  allow/deny、所用策略版本、命中依据（basis）与人类可读说明；
  不包含任何密钥或凭据材料。
* **判定一致**：策略引擎在判定前确保加载最新版本，同版本策略对同一
  请求必得同一结论；策略版本被写入结论与每条日志。
* **拒绝原因可区分**：令牌类错误透传 :class:`TokenError` 的细分原因；
  属性缺失透传 :class:`PolicyError(MISSING_ATTRIBUTE)`；凭据类错误
  透传 :class:`CredentialError`。
* **日志可串联**：每条日志带 request_id / policy_version；令牌与
  凭据内容永不入日志（统一经 :func:`redact` 处理）。
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from ztauth.credentials import CredentialVault, IssuedCredential
from ztauth.errors import PolicyError, TokenError
from ztauth.keyring import Keyring
from ztauth.logging_utils import (
    get_logger,
    reset_request_context,
    safe_kwargs,
    set_policy_version,
    set_request_context,
)
from ztauth.policy import (
    AuthzDecision,
    AuthzRequest,
    HotReloadPolicyEngine,
)
from ztauth.tokens import RevocationList, TokenClaims, verify_token


@dataclass(frozen=True, slots=True)
class AuthResult:
    """鉴权+授权结论（可记录、可复现；不含任何敏感材料）。"""

    request_id: str
    principal: str
    allowed: bool
    policy_version: int
    basis: str
    detail: str


@dataclass(frozen=True, slots=True)
class CredentialResult:
    """凭据读取结论（auth 可安全记录；issued.secret 禁止记录）。"""

    auth: AuthResult
    issued: IssuedCredential


def new_request_id() -> str:
    """生成本地请求标识。"""
    return "req-" + secrets.token_hex(8)


class AuthGateway:
    """组合密钥环、策略引擎与凭据保险库的门面。"""

    def __init__(
        self,
        keyring: Keyring,
        policies: HotReloadPolicyEngine,
        vault: CredentialVault,
        *,
        revocation: RevocationList | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keyring = keyring
        self._policies = policies
        self._vault = vault
        self._revocation = revocation
        self._clock = clock
        self._log = get_logger("engine")

    # ------------------------------------------------------------------ #
    def authenticate(
        self,
        token: str,
        *,
        request_id: str = "",
    ) -> TokenClaims:
        """仅做令牌校验。失败抛 TokenError（细分原因可区分）。"""
        rid = request_id or new_request_id()
        ctx = set_request_context(rid)
        try:
            self._log.info("authenticate start")
            try:
                claims = verify_token(
                    token,
                    self._keyring,
                    revocation=self._revocation,
                    clock=self._clock,
                )
            except TokenError as exc:
                self._log.warning(
                    "authenticate rejected %s",
                    safe_kwargs(reason=exc.reason),
                )
                raise
            self._log.info(
                "authenticate ok %s",
                safe_kwargs(principal=claims.sub, kid=claims.kid, jti=claims.jti),
            )
            return claims
        finally:
            reset_request_context(ctx)

    # ------------------------------------------------------------------ #
    def authorize(
        self,
        token: str,
        req: AuthzRequest,
        *,
        request_id: str = "",
    ) -> AuthResult:
        """校验令牌并做策略判定，返回可复现结论。"""
        rid = request_id or new_request_id()
        ctx = set_request_context(rid)
        try:
            claims = self.authenticate(token, request_id=rid)

            # 主体以令牌为准，忽略请求自报身份，避免越权伪造
            bound = AuthzRequest(
                principal=claims.sub,
                action=req.action,
                resource=req.resource,
                # 令牌属性与请求属性合并；请求属性不可覆盖令牌中同名属性
                attributes={**req.attributes, **dict(claims.attributes)},
            )
            self._log.info(
                "authorize evaluating %s",
                safe_kwargs(
                    principal=bound.principal,
                    action=bound.action,
                    resource=bound.resource,
                ),
            )
            decision: AuthzDecision = self._policies.decide(bound)
            set_policy_version(decision.version)
            result = AuthResult(
                request_id=rid,
                principal=claims.sub,
                allowed=decision.decision == "allow",
                policy_version=decision.version,
                basis=decision.basis,
                detail=decision.reason,
            )
            self._log.info(
                "authorize decision %s",
                safe_kwargs(
                    principal=claims.sub,
                    action=bound.action,
                    resource=bound.resource,
                    allowed=result.allowed,
                    policy_version=result.policy_version,
                    basis=result.basis,
                    detail=result.detail,
                ),
            )
            return result
        finally:
            reset_request_context(ctx)

    # ------------------------------------------------------------------ #
    def get_credential(
        self,
        token: str,
        req: AuthzRequest,
        *,
        caller_scopes: Iterable[str] = (),
        version: int | None = None,
        for_rotation: bool = False,
        request_id: str = "",
    ) -> CredentialResult:
        """完整链路：鉴权 -> 授权 -> 最小权限读取凭据。"""
        rid = request_id or new_request_id()
        ctx = set_request_context(rid)
        try:
            auth = self.authorize(token, req, request_id=rid)
            set_policy_version(auth.policy_version)
            if not auth.allowed:
                # 未授权绝不触碰凭据；用策略版本构造一个 allow=False 的决策
                decision = AuthzDecision(
                    decision="deny",
                    version=auth.policy_version,
                    basis=auth.basis,
                    reason=auth.detail,
                    matched_rule=None if auth.basis == "default_deny" else auth.basis,
                )
            else:
                decision = AuthzDecision(
                    decision="allow",
                    version=auth.policy_version,
                    basis=auth.basis,
                    reason=auth.detail,
                    matched_rule=auth.basis,
                )

            # 作用域以令牌声明为准时由调用方显式传入；此处仅记录，不泄露
            scopes = tuple(caller_scopes)
            self._log.info(
                "credential read %s",
                safe_kwargs(
                    name=req.resource,
                    version=version if version is not None else "active",
                    scope_count=len(scopes),
                ),
            )
            issued = self._vault.read(
                req.resource,
                decision,
                caller_scopes=scopes,
                version=version,
                for_rotation=for_rotation,
            )
            self._log.info(
                "credential issued %s",
                safe_kwargs(
                    name=issued.name,
                    version=issued.version,
                    state=issued.state,
                ),
            )
            return CredentialResult(auth=auth, issued=issued)
        finally:
            reset_request_context(ctx)
