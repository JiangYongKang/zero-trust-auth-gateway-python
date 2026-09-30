"""鉴权门面：令牌校验 -> 策略判定 -> 凭据读取，给出一致可解释的结论。

链路顺序与失败语义：
1. 令牌校验失败：直接抛出带 DenyReason 的 AuthError（过期/撤销/签名/未知 kid 可区分）。
2. 策略判定：取本次固定的不可变策略快照并评估；INDETERMINATE_MISSING_ATTRIBUTE
   映射为 POLICY_MISSING_ATTRIBUTE，与 POLICY_DENY 区分。
3. 仅当判定 ALLOW 才读取凭据；凭据层再做最小权限与版本校验。
每一步都写审计日志；任何日志/异常都不含令牌或凭据明文。

发布批次模式（构造时传入 ReleaseManager）：
- authorize 开始时 acquire() 固定当前批次，密钥/策略/凭据全部取自同一个
  Release 对象；请求结束前发生 publish/rollback 不影响本次结论。
- 结论（成功与失败）都带实际使用的 release_id，审计日志同样记录。
未传入 ReleaseManager 时走原有单项组件路径，行为与历史版本完全一致。
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import threading
from collections.abc import Callable

from .audit import AuditEntry, AuditLogger
from .credentials import CredentialStore, IssuedCredential, read_credential
from .errors import AuthError, DenyReason
from .keys import KeyRing, LookupResult
from .policy import Decision, Effect, Policy, PolicyStore, evaluate
from .releases import Release, ReleaseManager
from .tokens import TokenVerifier


@dataclasses.dataclass(frozen=True)
class AuthzResult:
    request_id: str
    subject: str
    decision: Decision
    credential: IssuedCredential | None
    release_id: int | None = None


class _ReleaseKeyView:
    """对 TokenVerifier 暴露与 KeyRing.lookup 同形的批次内密钥视图。

    未知 kid 委托 ReleaseManager 做受控回源（single-flight + 有界负缓存）；
    即使回源发布了含该 kid 的新批次，本视图仍固定原批次 -> 返回 unknown，
    保证请求不跨批。
    """

    def __init__(self, manager: ReleaseManager, release: Release) -> None:
        self._manager = manager
        self._release = release
        self._by_kid = {k.kid: k for k in release.content.keys}

    def lookup(
        self, kid: str, *, now: dt.datetime | None = None
    ) -> LookupResult:
        now = now or dt.datetime.now(dt.timezone.utc)
        key = self._by_kid.get(kid)
        if key is not None:
            within = key.not_before <= now < key.not_after
            return LookupResult("found" if within else "outside_window", key)
        # 源异常直接向上抛，由 TokenVerifier 映射为 token_key_reload_unavailable
        self._manager.reload_for_unknown_kid(self._release, kid)
        return LookupResult("unknown")


class _FrozenCredentialStore:
    """把批次内不可变凭据字典适配成 read_credential 需要的 store 接口。"""

    def __init__(self, creds: dict) -> None:
        self._creds = creds

    def load_all(self) -> dict:
        return self._creds  # 批次对象本身不可变，直接返回引用


@dataclasses.dataclass(frozen=True)
class _View:
    """一次请求固定的三段组件视图。"""

    verifier: TokenVerifier
    policy: Policy
    credentials: CredentialStore
    release_id: int | None


class Gateway:
    def __init__(
        self,
        ring: KeyRing | None = None,
        policies: PolicyStore | None = None,
        credentials: CredentialStore | None = None,
        audit: AuditLogger | None = None,
        *,
        released: ReleaseManager | None = None,
        revoked: "set[str] | None" = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self._verifier = TokenVerifier(ring) if ring is not None else None
        self._policies = policies
        self._credentials = credentials
        self._releases = released
        if released is None and (ring is None or policies is None or credentials is None):
            raise ValueError(
                "provide either ring/policies/credentials or a ReleaseManager"
            )
        self._audit = audit or AuditLogger()
        self._revoked_lock = threading.Lock()
        self._revoked: set[str] = set(revoked or ())
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def revoke_jti(self, jti: str) -> None:
        with self._revoked_lock:
            self._revoked.add(jti)

    def reload_policies(self) -> int:
        """策略热更新入口（兼容原有单项路径）；批次模式请用 publish/rollback。"""
        if self._releases is not None:
            return self._releases.current().content.policy.version
        return self._policies.reload()

    def publish(self, content=None) -> int:
        """发布一批新配置，返回单调递增的发布标识。"""
        assert self._releases is not None, "ReleaseManager not configured"
        return self._releases.publish(content)

    def rollback(self, release_id: int) -> int:
        """回退到保留期内的历史批次，立即对后续请求生效。"""
        assert self._releases is not None, "ReleaseManager not configured"
        return self._releases.rollback(release_id)

    def current_release_id(self) -> int:
        assert self._releases is not None, "ReleaseManager not configured"
        return self._releases.current_id()

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
        if self._releases is None:
            acquire_cm: contextlib.AbstractContextManager = contextlib.nullcontext(None)
        else:
            acquire_cm = self._releases.acquire()
        with acquire_cm as release:
            view = self._bind_view(release)
            return self._authorize_once(
                request_id, token, action, resource,
                credential_version=credential_version, now=now, view=view,
            )

    def _bind_view(self, release: Release | None) -> _View:
        if release is None:
            assert self._verifier is not None and self._policies is not None
            assert self._credentials is not None
            return _View(self._verifier, self._policies.current(),
                         self._credentials, None)
        return _View(
            TokenVerifier(_ReleaseKeyView(self._releases, release)),
            release.content.policy,
            _FrozenCredentialStore(release.content.credentials),
            release.id,
        )

    def _authorize_once(
        self,
        request_id: str,
        token: str,
        action: str,
        resource: str,
        *,
        credential_version: int | None,
        now: dt.datetime,
        view: _View,
    ) -> AuthzResult:
        rid = view.release_id

        # 1) 令牌校验（subject 未知时用占位，绝不记录令牌本身）
        try:
            with self._revoked_lock:
                revoked = set(self._revoked)
            claims = view.verifier.verify(token, revoked=revoked, now=now)
        except AuthError as exc:
            self._audit.deny(
                request_id, "<unauthenticated>", action, resource,
                f"authn_failed:{exc.reason.value}:{exc.detail or ''}".rstrip(":"),
                release_id=rid,
            )
            if rid is not None:
                exc.release_id = rid
            raise

        subject = claims.sub

        # 2) 策略判定：固定本次使用的策略快照与版本，保证结论可复现
        decision = evaluate(
            view.policy,
            subject=dict(claims.attrs),
            roles=claims.roles,
            action=action,
            resource=resource,
        )
        if decision.effect == Effect.INDETERMINATE_MISSING_ATTRIBUTE:
            self._audit.deny(request_id, subject, action, resource,
                             decision.reason, decision.policy_version,
                             release_id=rid)
            exc = AuthError(DenyReason.POLICY_MISSING_ATTRIBUTE, decision.reason)
            if rid is not None:
                exc.release_id = rid
            raise exc
        if decision.effect == Effect.DENY:
            self._audit.deny(request_id, subject, action, resource,
                             decision.reason, decision.policy_version,
                             release_id=rid)
            exc = AuthError(DenyReason.POLICY_DENY, decision.reason)
            if rid is not None:
                exc.release_id = rid
            raise exc

        # 3) 允许后读取凭据（凭据名约定为 resource）
        credential: IssuedCredential | None = None
        try:
            credential = read_credential(
                view.credentials, resource,
                roles=claims.roles, version=credential_version, now=now,
            )
        except AuthError as exc:
            self._audit.deny(request_id, subject, action, resource,
                             f"credential_failed:{exc.reason.value}",
                             decision.policy_version, release_id=rid)
            if rid is not None:
                exc.release_id = rid
            raise
        except Exception as exc:  # 防御：意外错误同样不得泄露内容
            self._audit.deny(request_id, subject, action, resource,
                             "credential_failed:internal_error",
                             decision.policy_version, release_id=rid)
            err = AuthError(DenyReason.CREDENTIAL_NOT_FOUND, "internal error")
            if rid is not None:
                err.release_id = rid
            raise err from exc

        self._audit.record(
            AuditEntry(
                request_id=request_id, subject=subject, action=action,
                resource=resource, effect="allow",
                policy_version=decision.policy_version,
                rationale=f"{decision.reason}; credential v{credential.version}",
                release_id=rid,
            )
        )
        return AuthzResult(request_id, subject, decision, credential, rid)
