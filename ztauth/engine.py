"""鉴权编排：令牌校验 → 策略判定 → 凭据读取，结论一致且可解释。"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable

from ztauth.credentials import CredentialVault, IssuedCredential
from ztauth.keyring import Keyring
from ztauth.policy import AuthzDecision, AuthzRequest, HotReloadPolicyEngine
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
    """凭据读取结论（同样不含可记录的 secret）。"""

    auth: AuthResult
    issued: IssuedCredential


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
        raise NotImplementedError

    def authenticate(
        self,
        token: str,
        *,
        request_id: str = "",
    ) -> TokenClaims:
        """仅做令牌校验，失败抛 TokenError（原因可区分）。"""
        raise NotImplementedError

    def authorize(
        self,
        token: str,
        req: AuthzRequest,
        *,
        request_id: str = "",
    ) -> AuthResult:
        """校验令牌并做策略判定，返回可复现结论。"""
        raise NotImplementedError

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
        """完整链路：鉴权 → 授权 → 最小权限读取凭据。"""
        raise NotImplementedError
