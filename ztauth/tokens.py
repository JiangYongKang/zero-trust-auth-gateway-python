"""HMAC-SHA256 签名令牌的签发与校验。

令牌格式（紧凑三段，base64url，无填充）：
    base64url(header_json).base64url(claims_json).base64url(hmac_sha256)
header = {"alg": "HS256", "typ": "ZT1", "kid": <密钥标识>}
claims = {"sub","jti","iat","exp","roles":[...],"attrs":{...}}
时间以 epoch 秒表示。
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import secrets

from .errors import AuthError, DenyReason
from .keys import KeyRing

_PREFIX = b"ZT1."


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(secret: bytes, signing_input: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


@dataclasses.dataclass(frozen=True)
class TokenClaims:
    sub: str
    jti: str
    iat: dt.datetime
    exp: dt.datetime
    roles: tuple[str, ...] = ()
    attrs: dict[str, str] = dataclasses.field(default_factory=dict)


class TokenIssuer:
    def __init__(self, ring: KeyRing) -> None:
        self._ring = ring

    def issue(
        self,
        sub: str,
        *,
        ttl: dt.timedelta,
        roles: tuple[str, ...] = (),
        attrs: dict[str, str] | None = None,
        jti: str | None = None,
        kid: str | None = None,
        now: dt.datetime | None = None,
    ) -> str:
        now = now or dt.datetime.now(dt.timezone.utc)
        if kid is not None:
            result = self._ring.lookup(kid, now=now)
            if result.kind != "found" or result.key is None:
                raise AuthError(DenyReason.TOKEN_UNKNOWN_KID, f"kid={kid}")
            key = result.key
        else:
            key = self._ring.current_signing_key(now=now)
        claims = {
            "sub": sub,
            "jti": jti or secrets.token_hex(8),
            "iat": now.timestamp(),
            "exp": (now + ttl).timestamp(),
            "roles": list(roles),
            "attrs": dict(attrs or {}),
        }
        header = {"alg": "HS256", "typ": "ZT1", "kid": key.kid}
        h_part = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        c_part = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{h_part}.{c_part}".encode()
        sig = _b64e(_sign(key.secret, signing_input))
        return f"{h_part}.{c_part}.{sig}"


class TokenVerifier:
    def __init__(self, ring: KeyRing) -> None:
        self._ring = ring

    def verify(
        self,
        token: str,
        *,
        revoked: "set[str] | None" = None,
        now: dt.datetime | None = None,
    ) -> TokenClaims:
        now = now or dt.datetime.now(dt.timezone.utc)
        revoked = revoked if revoked is not None else set()
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise AuthError(DenyReason.TOKEN_MALFORMED, "token must be 3 non-empty parts")
        h_b64, c_b64, s_b64 = parts
        try:
            header = json.loads(_b64d(h_b64))
            kid = header["kid"]
            if header.get("alg") != "HS256" or header.get("typ") != "ZT1":
                raise KeyError
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "bad header") from exc

        # 未知 kid：KeyRing 内部已做受控重载；源异常映射为"重载不可用"
        try:
            lookup = self._ring.lookup(kid, now=now)
        except AuthError:
            raise
        except Exception as exc:  # 密钥源不可用：受控重载失败，而非直接判未知
            raise AuthError(
                DenyReason.TOKEN_KEY_RELOAD_UNAVAILABLE,
                "key source unreachable during controlled reload",
            ) from exc
        if lookup.kind == "unknown":
            raise AuthError(DenyReason.TOKEN_UNKNOWN_KID, f"kid={kid}")
        assert lookup.key is not None
        if lookup.kind == "outside_window":
            # 密钥已退出轮换窗口：其签名不再被信任
            raise AuthError(
                DenyReason.TOKEN_SIGNATURE_MISMATCH,
                f"kid={kid} outside validity window",
            )

        try:
            sig = _b64d(s_b64)
        except ValueError as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "bad signature encoding") from exc
        expected = _sign(lookup.key.secret, f"{h_b64}.{c_b64}".encode())
        if not hmac.compare_digest(sig, expected):
            raise AuthError(DenyReason.TOKEN_SIGNATURE_MISMATCH, "hmac mismatch")

        try:
            raw = json.loads(_b64d(c_b64))
            claims = TokenClaims(
                sub=str(raw["sub"]),
                jti=str(raw["jti"]),
                iat=dt.datetime.fromtimestamp(float(raw["iat"]), tz=dt.timezone.utc),
                exp=dt.datetime.fromtimestamp(float(raw["exp"]), tz=dt.timezone.utc),
                roles=tuple(raw.get("roles", ())),
                attrs=dict(raw.get("attrs", {})),
            )
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "bad claims") from exc

        if now >= claims.exp:
            raise AuthError(DenyReason.TOKEN_EXPIRED, f"exp={claims.exp.isoformat()}")
        if claims.jti in revoked:
            raise AuthError(DenyReason.TOKEN_REVOKED, f"jti={claims.jti}")
        return claims
