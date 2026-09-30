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
from .credentials import (
    Credential,
    CredentialStore,
    FrozenCredentialStore,
    IssuedCredential,
    read_credential,
)
from .errors import AuthError, DenyReason
from .keys import KeyRing, SigningKey
from .policy import Decision, Effect, Policy, PolicyStore, evaluate
from .releases import ReleaseManager
from .tokens import TokenVerifier


@dataclasses.dataclass(frozen=True)
class AuthzResult:
    request_id: str
    subject: str
    decision: Decision
    credential: IssuedCredential | None
    # 本次请求实际使用的发布批次（未启用发布批次时为 None）
    release_id: int | None = None


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
        releases: ReleaseManager | None = None,
    ) -> None:
        self._verifier = TokenVerifier(ring)
        self._policies = policies
        self._credentials = credentials
        self._audit = audit or AuditLogger()
        self._revoked_lock = threading.Lock()
        self._revoked: set[str] = set(revoked or ())
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        # 发布批次管理器可选；提供后鉴权走"批次固定"路径
        self._releases = releases
        self._ring = ring

    def revoke_jti(self, jti: str) -> None:
        with self._revoked_lock:
            self._revoked.add(jti)

    def reload_policies(self) -> int:
        """策略热更新入口：无需重启即可生效（原有单项热更新路径）。"""
        return self._policies.reload()

    # ---- 发布批次 ----------------------------------------------------------

    def publish_batch(
        self,
        *,
        keys: tuple[SigningKey, ...] | None = None,
        key_version: int | None = None,
        policy: Policy | None = None,
        credentials: dict[str, Credential] | None = None,
    ) -> int:
        """把新的一组密钥/策略/凭据作为一个批次原子发布，返回单调发布标识。

        任一部分省略时，取对应单项组件的当前快照（与单项轮换/热更新兼容：
        可先 rotate/reload 到各自目标态，再调用本方法把三者打包成同一批次）。
        """
        if self._releases is None:
            raise RuntimeError("未启用发布批次：构造 Gateway 时需传入 releases")
        cur_keys, cur_key_version = self._ring.snapshot()
        if keys is None:
            keys = cur_keys
        if key_version is None:
            key_version = cur_key_version
        if policy is None:
            policy = self._policies.current()
        if credentials is None:
            credentials = self._credentials.load_all()
        return self._releases.publish(
            tuple(keys), key_version, policy, dict(credentials)
        )

    def rollback_batch(self, release_id: int) -> int:
        """按发布标识整批回退；异常类型区分"从未存在"与"已超保留期"。"""
        if self._releases is None:
            raise RuntimeError("未启用发布批次：构造 Gateway 时需传入 releases")
        return self._releases.rollback(release_id)

    def current_release_id(self) -> int | None:
        return self._releases.current_id if self._releases else None

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
            return self._authorize_legacy(
                request_id, token, action, resource,
                credential_version=credential_version, now=now,
            )

        # 发布批次路径：进入即 pin 住批次，整请求不跨批次混用。
        # 未知 kid 至多触发一次代际受控刷新；若刷新带回了新批次，则整请求
        # 从第一步重新开始（绝不用批次 A 的密钥 + 批次 B 的策略/凭据）。
        rid_at_entry: int | None = None
        for attempt in (1, 2):
            with self._releases.use_current() as bundle:
                rid = bundle.release_id
                rid_at_entry = rid
                claims = self._verify_token(
                    request_id, token, action, resource, bundle.ring, now, rid,
                )
                if claims is None:
                    # 仅"未知 kid"走到这里：尝试一次受控刷新
                    new_rid: int | None = None
                    if attempt == 1:
                        try:
                            new_rid = self._releases.try_refresh_for_unknown_kid()
                        except AuthError:
                            raise
                        except Exception as exc:
                            # 上游发布源不可用：与单项路径一致，单列原因而非误判未知
                            self._audit.deny(
                                request_id, "<unauthenticated>", action, resource,
                                f"[release {rid}] authn_failed:"
                                f"{DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE.value}",
                                None, rid,
                            )
                            raise AuthError(
                                DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE,
                                "release source unreachable during controlled refresh",
                            ) from exc
                    if attempt == 1 and new_rid is not None and new_rid != rid:
                        continue
                    self._audit.deny(
                        request_id, "<unauthenticated>", action, resource,
                        f"[release {rid}] authn_failed:token_unknown_kid",
                        None, rid,
                    )
                    raise AuthError(DenyReason.TOKEN_UNKNOWN_KID, "unknown kid")
                subject = claims.sub
                decision = evaluate(
                    bundle.policy,
                    subject=dict(claims.attrs),
                    roles=claims.roles,
                    action=action,
                    resource=resource,
                )
                if decision.effect == Effect.INDETERMINATE_MISSING_ATTRIBUTE:
                    self._audit.deny(request_id, subject, action, resource,
                                     decision.reason, decision.policy_version, rid)
                    raise AuthError(DenyReason.POLICY_MISSING_ATTRIBUTE, decision.reason)
                if decision.effect == Effect.DENY:
                    self._audit.deny(request_id, subject, action, resource,
                                     decision.reason, decision.policy_version, rid)
                    raise AuthError(DenyReason.POLICY_DENY, decision.reason)

                store = FrozenCredentialStore(bundle.credentials)
                credential = self._read_credential(
                    request_id, subject, action, resource, store,
                    roles=claims.roles, version=credential_version,
                    now=now, policy_version=decision.policy_version,
                    release_id=rid,
                )
                self._audit.record(
                    AuditEntry(
                        request_id=request_id, subject=subject, action=action,
                        resource=resource, effect="allow",
                        policy_version=decision.policy_version,
                        rationale=(
                            f"[release {rid}] {decision.reason}; "
                            f"credential v{credential.version}"
                        ),
                        release_id=rid,
                    )
                )
                return AuthzResult(request_id, subject, decision, credential, rid)
        # 理论不可达：未知 kid 重试至多一次
        raise AuthError(  # pragma: no cover
            DenyReason.TOKEN_UNKNOWN_KID,
            f"unknown kid after refresh (release {rid_at_entry})",
        )

    # ---- 原单项链路（未启用发布批次时，行为与历史完全一致）----------------

    def _authorize_legacy(
        self,
        request_id: str,
        token: str,
        action: str,
        resource: str,
        *,
        credential_version: int | None,
        now: dt.datetime,
    ) -> AuthzResult:
        claims = self._verify_token(
            request_id, token, action, resource, self._ring, now, None,
        )
        assert claims is not None
        subject = claims.sub

        # 策略判定：固定本次使用的策略快照与版本，保证结论可复现
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

        credential = self._read_credential(
            request_id, subject, action, resource, self._credentials,
            roles=claims.roles, version=credential_version, now=now,
            policy_version=decision.policy_version, release_id=None,
        )
        self._audit.record(
            AuditEntry(
                request_id=request_id, subject=subject, action=action,
                resource=resource, effect="allow",
                policy_version=decision.policy_version,
                rationale=f"{decision.reason}; credential v{credential.version}",
            )
        )
        return AuthzResult(request_id, subject, decision, credential)

    # ---- 共用步骤 ----------------------------------------------------------

    def _verify_token(self, request_id, token, action, resource, ring, now, rid):
        """校验令牌；成功返回 claims，未知 kid 返回 None（不写审计）。

        其余失败直接抛出 AuthError，审计已写。未知 kid 单独返回 None，由调用
        方决定是否触发发布批次的受控刷新。
        """
        try:
            with self._revoked_lock:
                revoked = set(self._revoked)
            return TokenVerifier(ring).verify(token, revoked=revoked, now=now)
        except AuthError as exc:
            if exc.reason is DenyReason.TOKEN_UNKNOWN_KID:
                return None
            prefix = f"[release {rid}] " if rid is not None else ""
            self._audit.deny(
                request_id, "<unauthenticated>", action, resource,
                f"{prefix}authn_failed:{exc.reason.value}:{exc.detail or ''}".rstrip(":"),
                None, rid,
            )
            raise

    def _read_credential(
        self, request_id, subject, action, resource, store,
        *, roles, version, now, policy_version, release_id,
    ) -> IssuedCredential:
        try:
            return read_credential(
                store, resource, roles=roles, version=version, now=now,
            )
        except AuthError as exc:
            self._audit.deny(request_id, subject, action, resource,
                             f"credential_failed:{exc.reason.value}",
                             policy_version, release_id)
            raise
        except Exception as exc:  # 防御：意外错误同样不得泄露内容
            self._audit.deny(request_id, subject, action, resource,
                             "credential_failed:internal_error",
                             policy_version, release_id)
            raise AuthError(DenyReason.CREDENTIAL_NOT_FOUND, "internal error") from exc
