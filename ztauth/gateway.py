"""鉴权门面：令牌校验 -> 策略判定 -> 凭据读取，给出一致可解释的结论。

链路顺序与失败语义：
1. 令牌校验失败：直接抛出带 DenyReason 的 AuthError（过期/撤销/签名/未知 kid 可区分）。
2. 策略判定：取当前不可变策略快照并评估；INDETERMINATE_MISSING_ATTRIBUTE
   映射为 POLICY_MISSING_ATTRIBUTE，与 POLICY_DENY 区分。
3. 仅当判定 ALLOW 才读取凭据；凭据层再做最小权限与版本校验。
每一步都写审计日志；任何日志/异常都不含令牌或凭据明文。
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import threading
from collections.abc import Callable

from .audit import AuditEntry, AuditLogger
from .credentials import CredentialStore, IssuedCredential, read_credential
from .errors import AuthError, DenyReason
from .keys import KeyRing
from .policy import Decision, Effect, PolicyStore, evaluate
from .tokens import TokenVerifier


@dataclasses.dataclass(frozen=True)
class AuthzResult:
    request_id: str
    subject: str
    decision: Decision
    credential: IssuedCredential | None


class Gateway:
    def __init__(
        self,
        ring: KeyRing,
        policies: PolicyStore,
        credentials: CredentialStore,
        audit: AuditLogger | None = None,
        *,
        revoked: "set[str] | None" = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self._verifier = TokenVerifier(ring)
        self._policies = policies
        self._credentials = credentials
        self._audit = audit or AuditLogger()
        self._revoked_lock = threading.Lock()
        self._revoked: set[str] = set(revoked or ())
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def revoke_jti(self, jti: str) -> None:
        with self._revoked_lock:
            self._revoked.add(jti)

    def reload_policies(self) -> int:
        """策略热更新入口：无需重启即可生效。"""
        return self._policies.reload()

    def authorize(
        self,
        request_id: str,
        token: str,
        action: str,
        resource: str,
        *,
        credential_version: int | None = None,
        now: dt.datetime | None = None,
    ) -> AuthzResult:
        now = now or self._clock()

        # 1) 令牌校验（subject 未知时用占位，绝不记录令牌本身）
        try:
            with self._revoked_lock:
                revoked = set(self._revoked)
            claims = self._verifier.verify(token, revoked=revoked, now=now)
        except AuthError as exc:
            self._audit.deny(
                request_id, "<unauthenticated>", action, resource,
                f"authn_failed:{exc.reason.value}:{exc.detail or ''}".rstrip(":"),
            )
            raise

        subject = claims.sub

        # 2) 策略判定：固定本次使用的策略快照与版本，保证结论可复现
        policy = self._policies.current()
        decision = evaluate(
            policy,
            subject=dict(claims.attrs),
            roles=claims.roles,
            action=action,
            resource=resource,
        )
        if decision.effect == Effect.INDETERMINATE_MISSING_ATTRIBUTE:
            self._audit.deny(request_id, subject, action, resource,
                             decision.reason, decision.policy_version)
            raise AuthError(DenyReason.POLICY_MISSING_ATTRIBUTE, decision.reason)
        if decision.effect == Effect.DENY:
            self._audit.deny(request_id, subject, action, resource,
                             decision.reason, decision.policy_version)
            raise AuthError(DenyReason.POLICY_DENY, decision.reason)

        # 3) 允许后读取凭据（凭据名约定为 resource）
        credential: IssuedCredential | None = None
        try:
            credential = read_credential(
                self._credentials, resource,
                roles=claims.roles, version=credential_version, now=now,
            )
        except AuthError as exc:
            self._audit.deny(request_id, subject, action, resource,
                             f"credential_failed:{exc.reason.value}",
                             decision.policy_version)
            raise
        except Exception as exc:  # 防御：意外错误同样不得泄露内容
            self._audit.deny(request_id, subject, action, resource,
                             "credential_failed:internal_error",
                             decision.policy_version)
            raise AuthError(DenyReason.CREDENTIAL_NOT_FOUND, "internal error") from exc

        self._audit.record(
            AuditEntry(
                request_id=request_id, subject=subject, action=action,
                resource=resource, effect="allow",
                policy_version=decision.policy_version,
                rationale=f"{decision.reason}; credential v{credential.version}",
            )
        )
        return AuthzResult(request_id, subject, decision, credential)
