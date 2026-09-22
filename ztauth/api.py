"""FastAPI 演示端点（内部调用）。

- POST /v1/authorize   鉴权 + 授权 + 凭据分发
- POST /v1/policies/reload  策略热更新
错误响应 {"error": <DenyReason>, "detail": ...}，detail 中不含凭据内容。
凭据明文只出现在 200 响应的 credential.secret 字段（base64），审计与日志只记版本号。
"""
from __future__ import annotations

import base64
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .errors import AuthError
from .gateway import Gateway


def _json_default(obj):  # noqa: ANN001
    import datetime as dt
    if isinstance(obj, (dt.datetime,)):
        return obj.isoformat()
    raise TypeError(type(obj).__name__)


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(title="zero-trust-auth-gateway", version="0.1.0")

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError):  # noqa: ANN202
        return JSONResponse(
            status_code=403,
            content={"error": exc.reason.value, "detail": exc.detail},
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

    return app
