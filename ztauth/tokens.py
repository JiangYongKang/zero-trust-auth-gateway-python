"""签名令牌：签发与校验，拒绝原因可区分。

令牌格式（紧凑、自包含）::

    base64url(payload_json) || "." || base64url(HMAC_SHA256(key, payload_b64))

其中 payload JSON 至少包含::

    {"v": 1, "kid": "...", "sub": "...", "jti": "...",
     "iat": <ts>, "exp": <ts>, "scopes": ["..."], "attrs": {...}}

校验顺序固定，保证拒绝原因彼此可区分：

1. 结构无法解析            -> ``token_malformed``
2. 未知 kid（含受控重载）  -> ``token_unknown_kid``（由密钥环抛出）
3. 签名不匹配（恒定时间）  -> ``token_signature_mismatch``
4. 尚未生效 / 已过期       -> ``token_not_yet_valid`` / ``token_expired``
5. 已撤销（按 jti）        -> ``token_revoked``

任何异常消息都只包含原因码与结构性元信息，绝不回显令牌或密钥内容。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from ztauth.errors import TokenError, TokenReasons
from ztauth.keyring import Key, Keyring

_TOKEN_VERSION = 1


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
    not_before: float = 0.0


class RevocationList(Protocol):
    """令牌撤销清单（按 jti 查询）。"""

    def is_revoked(self, jti: str) -> bool:
        ...


class SetRevocationList:
    """进程内撤销清单：测试与本地演示用。"""

    def __init__(self, revoked: frozenset[str] | set[str] | None = None) -> None:
        self._revoked: set[str] = set(revoked or ())

    def revoke(self, jti: str) -> None:
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


# ---------------------------------------------------------------------- #
# base64url 工具
# ---------------------------------------------------------------------- #
def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _mac(key: Key, payload_b64: str) -> bytes:
    return hmac.new(key.secret, payload_b64.encode("ascii"), hashlib.sha256).digest()


# ---------------------------------------------------------------------- #
# 签发
# ---------------------------------------------------------------------- #
def issue_token(
    keyring: Keyring,
    *,
    sub: str,
    ttl_seconds: float = 300.0,
    scopes: frozenset[str] | set[str] = frozenset(),
    attributes: Mapping[str, str] | None = None,
    jti: str | None = None,
    clock: Callable[[], float] = time.time,
    not_before: float | None = None,
) -> tuple[str, TokenClaims]:
    """用密钥环当前首选（严格 active）密钥签发令牌。"""
    if not sub:
        raise TokenError("empty subject", reason=TokenReasons.MALFORMED)
    if ttl_seconds <= 0:
        raise TokenError("non-positive ttl", reason=TokenReasons.MALFORMED)

    now = clock()
    key = keyring.signing_key()
    jti = jti or secrets.token_urlsafe(18)
    nbf = now if not_before is None else not_before

    payload = {
        "v": _TOKEN_VERSION,
        "kid": key.kid,
        "sub": sub,
        "jti": jti,
        "iat": now,
        "nbf": nbf,
        "exp": now + ttl_seconds,
        "scopes": sorted(set(scopes)),
        "attrs": dict(attributes or {}),
    }
    payload_b64 = _b64u_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    mac_b64 = _b64u_encode(_mac(key, payload_b64))

    claims = TokenClaims(
        sub=sub,
        kid=key.kid,
        issued_at=now,
        expires_at=now + ttl_seconds,
        scopes=frozenset(payload["scopes"]),
        jti=jti,
        attributes=dict(payload["attrs"]),
        not_before=nbf,
    )
    return f"{payload_b64}.{mac_b64}", claims


# ---------------------------------------------------------------------- #
# 校验
# ---------------------------------------------------------------------- #
def _fail(reason: str) -> "TokenError":
    # 消息即原因码，绝不回显令牌内容
    return TokenError(reason, reason=reason)


def verify_token(
    token: str,
    keyring: Keyring,
    *,
    revocation: RevocationList | None = None,
    clock: Callable[[], float] = time.time,
) -> TokenClaims:
    """校验令牌并返回声明；失败抛 :class:`TokenError`（原因可区分）。"""
    if not isinstance(token, str) or token.count(".") != 1:
        raise _fail(TokenReasons.MALFORMED)
    payload_b64, mac_b64 = token.split(".", 1)
    if not payload_b64 or not mac_b64:
        raise _fail(TokenReasons.MALFORMED)

    try:
        payload = json.loads(_b64u_decode(payload_b64).decode("utf-8"))
        provided_mac = _b64u_decode(mac_b64)
    except Exception as exc:  # base64 / json / 编码错误
        raise _fail(TokenReasons.MALFORMED) from exc

    if not isinstance(payload, dict):
        raise _fail(TokenReasons.MALFORMED)
    kid = payload.get("kid")
    if not isinstance(kid, str) or not kid:
        raise _fail(TokenReasons.MALFORMED)

    # 未知 kid：密钥环内部做受控（单飞）重载，仍未知则抛 unknown_kid
    key = keyring.verify_key(kid)

    # 签名恒定时间比对（在时间窗口校验之前，伪造令牌无法通过这一步）
    expected_mac = _mac(key, payload_b64)
    if not hmac.compare_digest(expected_mac, provided_mac):
        raise _fail(TokenReasons.SIGNATURE_MISMATCH)

    # 签名可信后再读取声明做时间/撤销判定
    try:
        sub = str(payload["sub"])
        jti = str(payload.get("jti", ""))
        iat = float(payload["iat"])
        exp = float(payload["exp"])
        nbf = float(payload.get("nbf", 0.0))
        scopes = frozenset(str(s) for s in payload.get("scopes", ()))
        raw_attrs = payload.get("attrs", {})
        attrs = {str(k): str(v) for k, v in raw_attrs.items()}
    except (KeyError, TypeError, ValueError) as exc:
        raise _fail(TokenReasons.MALFORMED) from exc

    now = clock()
    if now < nbf:
        raise _fail(TokenReasons.NOT_YET_VALID)
    if now >= exp:
        raise _fail(TokenReasons.EXPIRED)
    if revocation is not None and jti and revocation.is_revoked(jti):
        raise _fail(TokenReasons.REVOKED)

    return TokenClaims(
        sub=sub,
        kid=kid,
        issued_at=iat,
        expires_at=exp,
        scopes=scopes,
        jti=jti,
        attributes=attrs,
        not_before=nbf,
    )
