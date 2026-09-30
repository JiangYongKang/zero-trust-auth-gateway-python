"""FastAPI 演示端点（内部调用）。

- POST /v1/authorize   鉴权 + 授权 + 凭据分发
- POST /v1/policies/reload  策略热更新（原有单项路径）
- POST /v1/releases/publish 发布一个新批次
- POST /v1/releases/rollback 回退到指定批次
错误响应 {"error": <DenyReason>, "detail": ..., "release_id": ...}，
detail 中不含凭据内容。
凭据明文只出现在 200 响应的 credential.secret 字段（base64），审计与日志只记版本号。
"""
from __future__ import annotations

import base64
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .errors import AuthError
from .gateway import Gateway
from .releases import ReleaseError


def _json_default(obj):  # noqa: ANN001
    import datetime as dt
    if isinstance(obj, (dt.datetime,)):
        return obj.isoformat()
    raise TypeError(type(obj).__name__)


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(title="zero-trust-auth-gateway", version="0.2.0")
    releases_enabled = gateway._releases is not None  # noqa: SLF001

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError):  # noqa: ANN202
        return JSONResponse(
            status_code=403,
            content={
                "error": exc.reason.value,
                "detail": exc.detail,
                "release_id": getattr(exc, "release_id", None),
            },
        )

    @app.exception_handler(ReleaseError)
    async def _release_error_handler(request: Request, exc: ReleaseError):  # noqa: ANN202
        return JSONResponse(
            status_code=404,
            content={"error": "release_" + exc.kind, "release_id": exc.release_id},
        )

    @app.post("/v1/authorize")
    async def authorize(request: Request):  # noqa: ANN201
        body = await request.json()
        request_id = request.headers.get("x-request-id") or f"req-{secrets.token_hex(6)}"
        result = gateway.authorize(
            request_id,
            body["token"],
            body["action"],
            body["resource"],
            credential_version=body.get("credential_version"),
        )
        cred = result.credential
        return {
            "request_id": request_id,
            "subject": result.subject,
            "effect": result.decision.effect.value,
            "policy_version": result.decision.policy_version,
            "release_id": result.release_id,
            "rationale": result.decision.reason,
            "credential": (
                None if cred is None else {
                    "name": cred.name,
                    "version": cred.version,
                    "not_after": cred.not_after.isoformat() if cred.not_after else None,
                    "secret": base64.b64encode(cred.secret).decode("ascii"),
                }
            ),
        }

    @app.post("/v1/policies/reload")
    async def reload_policies():  # noqa: ANN201
        return {"policy_version": gateway.reload_policies()}

    if releases_enabled:
        @app.post("/v1/releases/current")
        async def current_release():  # noqa: ANN201
            return {"release_id": gateway.current_release_id()}

        @app.post("/v1/releases/publish")
        async def publish_release():  # noqa: ANN201
            # 从已配置的发布源读取最新整批并发布；内容编排请在源侧完成
            rid = gateway.publish()
            return {"release_id": rid}

        @app.post("/v1/releases/rollback")
        async def rollback_release(request: Request):  # noqa: ANN201
            body = await request.json()
            rid = gateway.rollback(int(body["release_id"]))
            return {"release_id": rid}

    return app
