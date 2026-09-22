"""端到端：FastAPI 端点的允许/拒绝/热更新，错误体不含凭据内容。"""
from __future__ import annotations

import datetime as dt

from fastapi.testclient import TestClient

from ztauth.api import create_app
from ztauth.tokens import TokenIssuer


def _client(gateway):
    return TestClient(create_app(gateway))


def test_authorize_success_returns_credential(gateway, ring):
    now = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)
    token = TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"team": "payments"}, now=now,
    )
    client = _client(gateway)
    resp = client.post(
        "/v1/authorize",
        json={"token": token, "action": "read", "resource": "db-payments"},
        headers={"x-request-id": "e2e-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["request_id"] == "e2e-1"
    assert body["effect"] == "allow"
    assert body["policy_version"] == 1
    assert body["credential"]["name"] == "db-payments"
    import base64
    assert base64.b64decode(body["credential"]["secret"]) == b"db-secret-v1"


def test_authorize_deny_body_distinguishes_reasons(gateway, ring):
    now = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)
    bad_token = "a.b.c"
    client = _client(gateway)
    resp = client.post(
        "/v1/authorize",
        json={"token": bad_token, "action": "read", "resource": "db-payments"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "token_malformed"
    assert "db-secret" not in resp.text


def test_policy_reload_endpoint(gateway):
    client = _client(gateway)
    resp = client.post("/v1/policies/reload")
    assert resp.status_code == 200
    assert resp.json()["policy_version"] == 1
