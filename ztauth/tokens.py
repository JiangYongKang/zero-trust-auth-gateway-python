"""签名令牌：签发与校验，拒绝原因可区分。

令牌为紧凑字符串：``base64url(payload_json).base64url(mac)``，
头部字段 ``kid`` 标识签名密钥。使用 HMAC-SHA256（本地密钥材料）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from ztauth.keyring import Keyring


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """校验通过后得到的令牌声明。"""

    sub: str
    kid: str
    issued_at: float
    expires_at: float
    scopes: frozenset[str] = frozenset()
    jti: str = ""
    attributes: Mapping[str, str] = None  # type: ignore[assignment]


class RevocationList(Protocol):
    """令牌撤销清单（按 jti 撤销）。"""

    def is_revoked(self, jti: str) -> bool:
        ...


def issue_token(
    keyring: Keyring,
    *,
    sub: str,
    ttl_seconds: float = 300.0,
    scopes: frozenset[str] | set[str] = frozenset(),
    attributes: Mapping[str, str] | None = None,
    jti: str | None = None,
    clock: Callable[[], float] = time.time,
) -> tuple[str, TokenClaims]:
    """用密钥环当前首选密钥签发令牌，返回 (令牌字符串, 声明)。"""
    raise NotImplementedError


def verify_token(
    token: str,
    keyring: Keyring,
    *,
    revocation: "RevocationList | None" = None,
    clock: Callable[[], float] = time.time,
) -> TokenClaims:
    """校验令牌。

    失败时抛出 :class:`ztauth.errors.TokenError`，reason 取
    :class:`ztauth.errors.TokenReasons` 中的可区分值。
    """
    raise NotImplementedError
