"""面向内部调用的零信任鉴权与凭据分发网关（FastAPI 薄层）。

仅暴露最小内部接口，所有判定逻辑都在 :mod:`ztauth` 内完成。
凭据明文只在 ``/internal/credentials/{name}`` 的一次性响应中交付，
其余任何响应/日志都不含密钥或凭据材料。

本地启动::

    uv run python -m ztauth.localconfig init ./local-material
    uv run uvicorn main:app --reload

材料目录可由环境变量 ``ZTAUTH_MATERIAL_DIR`` 覆盖，默认 ``./local-material``。
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ztauth import logging_utils
from ztauth.engine import AuthGateway, new_request_id
from ztauth.errors import AuthError, CredentialError, PolicyError, TokenError
from ztauth.localconfig import build_gateway
from ztauth.policy import AuthzRequest

logging_utils.configure_logging()

_MATERIAL_DIR = os.environ.get("ZTAUTH_MATERIAL_DIR", "./local-material")
_gateway: AuthGateway | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _gateway
    # 允许未初始化时启动（便于先起服务再生成材料）；按需懒加载
    if os.path.isdir(_MATERIAL_DIR):
        _gateway, *_ = build_gateway(_MATERIAL_DIR)
    yield


app = FastAPI(title="Zero-Trust Auth Gateway (internal)", lifespan=lifespan)


def gateway() -> AuthGateway:
    global _gateway
    if _gateway is None:
        if not os.path.isdir(_MATERIAL_DIR):
            raise HTTPException(
                status_code=503,
                detail=(
                    "material directory not found; run "
                    "'python -m ztauth.localconfig init "
                    f"{_MATERIAL_DIR}'"
                ),
            )
        _gateway, *_ = build_gateway(_MATERIAL_DIR)
    return _gateway


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def _rid(request: Request) -> str:
    return request.headers.get("x-request-id") or new_request_id()


def _map_auth_error(exc: AuthError) -> HTTPException:
    # 令牌问题 -> 401；属性缺失 -> 422（区别于 403 拒绝）；
    # 凭据问题中越权 -> 403，不存在/失效版本 -> 404/409
    if isinstance(exc, TokenError):
        return HTTPException(status_code=401, detail={"reason": exc.reason})
    if isinstance(exc, PolicyError):
        status = 422 if exc.reason == "policy_missing_attribute" else 403
        return HTTPException(status_code=status, detail={"reason": exc.reason})
    if isinstance(exc, CredentialError):
        status = {
            "credential_not_found": 404,
            "credential_version_not_found": 404,
            "credential_version_retired": 409,
            "credential_scope_denied": 403,
            "credential_not_readable": 409,
        }.get(exc.reason, 403)
        return HTTPException(status_code=status, detail={"reason": exc.reason})
    return HTTPException(status_code=500, detail={"reason": exc.reason})


class AuthzBody(BaseModel):
    action: str = Field(..., examples=["read"])
    resource: str = Field(..., examples=["db"])
    attributes: dict[str, str] = Field(default_factory=dict)


class CredentialBody(AuthzBody):
    version: int | None = None
    scopes: list[str] = Field(default_factory=list)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/verify")
def verify(
    body: AuthzBody,
    request: Request,
    authorization: str | None = Header(default=None),
    gw: AuthGateway = Depends(gateway),
) -> dict[str, Any]:
    token = _bearer(authorization)
    try:
        claims = gw.authenticate(token, request_id=_rid(request))
    except AuthError as exc:
        raise _map_auth_error(exc)
    return {
        "principal": claims.sub,
        "kid": claims.kid,
        "expires_at": claims.expires_at,
        "scopes": sorted(claims.scopes),
    }


@app.post("/internal/authorize")
def authorize(
    body: AuthzBody,
    request: Request,
    authorization: str | None = Header(default=None),
    gw: AuthGateway = Depends(gateway),
) -> dict[str, Any]:
    token = _bearer(authorization)
    rid = _rid(request)
    req = AuthzRequest(
        principal="", action=body.action, resource=body.resource,
        attributes=body.attributes,
    )
    try:
        result = gw.authorize(token, req, request_id=rid)
    except AuthError as exc:
        raise _map_auth_error(exc)
    return {
        "request_id": rid,
        "allowed": result.allowed,
        "policy_version": result.policy_version,
        "basis": result.basis,
        "detail": result.detail,
    }


@app.post("/internal/credentials/{name}")
def get_credential(
    name: str,
    body: CredentialBody,
    request: Request,
    authorization: str | None = Header(default=None),
    gw: AuthGateway = Depends(gateway),
) -> dict[str, Any]:
    token = _bearer(authorization)
    rid = _rid(request)
    # 路径参数即资源名；body.resource 若提供必须一致，避免歧义
    if body.resource and body.resource != name:
        raise HTTPException(
            status_code=400,
            detail={"reason": "resource_name_mismatch"},
        )
    req = AuthzRequest(
        principal="", action=body.action, resource=name,
        attributes=body.attributes,
    )
    try:
        result = gw.get_credential(
            token, req,
            caller_scopes=body.scopes,
            version=body.version,
            request_id=rid,
        )
    except AuthError as exc:
        raise _map_auth_error(exc)
    return {
        "request_id": rid,
        "allowed": True,
        "policy_version": result.auth.policy_version,
        "basis": result.auth.basis,
        "credential": {
            "name": result.issued.name,
            "version": result.issued.version,
            "secret": result.issued.secret,  # 一次性交付；不写日志
            "expires_at": result.issued.expires_at,
            "state": result.issued.state,
        },
    }
