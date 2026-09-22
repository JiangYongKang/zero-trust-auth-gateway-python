"""FastAPI 内部接口端到端测试（TestClient，本地材料、无网络）。"""

from __future__ import annotations

import pytest

# main 在导入时读取环境变量；这里统一指向不存在的目录，由测试内注入网关
import os
os.environ.setdefault("ZTAUTH_MATERIAL_DIR", "/tmp/zt-nonexistent-dir")

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from ztauth.tokens import issue_token  # noqa: E402


@pytest.fixture()
def client(gateway):
    main._gateway = gateway
    with TestClient(main.app) as c:
        yield c
    main._gateway = None


def _auth_headers(tok, rid=None):
    h = {"Authorization": f"Bearer {tok}"}
    if rid:
        h["x-request-id"] = rid
    return h


def test_healthz(client) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_authorize_allow_returns_version_and_basis(client, gateway, make_token) -> None:
    tok = make_token(gateway)
    r = client.post(
        "/internal/authorize",
        json={"action": "read", "resource": "db", "attributes": {"dept": "eng"}},
        headers=_auth_headers(tok, "rid-api-1"),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is True
    assert body["policy_version"] == 1
    assert body["basis"] == "allow-alice-db"
    assert body["request_id"] == "rid-api-1"


def test_authorize_deny_is_403_ish_and_distinguishable(client, gateway, make_token) -> None:
    # carol 命中显式 deny -> 200 allowed=false（授权判定本身成功）
    tok = make_token(gateway, sub="carol")
    r = client.post(
        "/internal/authorize",
        json={"action": "read", "resource": "db", "attributes": {"dept": "eng"}},
        headers=_auth_headers(tok),
    )
    assert r.status_code == 200 and r.json()["allowed"] is False

    # 坏令牌 -> 401 + 细分原因
    r = client.post(
        "/internal/authorize", json={"action": "read", "resource": "db"},
        headers=_auth_headers("garbage"),
    )
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "token_malformed"

    # 缺属性 -> 422，与 403 拒绝区分
    tok_no_attr = make_token(gateway, sub="alice", attrs={})
    r = client.post(
        "/internal/authorize",
        json={"action": "read", "resource": "db"},
        headers=_auth_headers(tok_no_attr),
    )
    assert r.status_code == 422
    assert r.json()["detail"]["reason"] == "policy_missing_attribute"


def test_credential_endpoint_full_chain_and_version_errors(client, gateway, make_token):
    tok = make_token(gateway)
    payload = {"action": "read", "resource": "db",
               "attributes": {"dept": "eng"}, "scopes": ["db:read"]}
    r = client.post("/internal/credentials/db", json=payload, headers=_auth_headers(tok))
    assert r.status_code == 200
    cred = r.json()["credential"]
    assert cred["version"] == 1 and cred["state"] == "active"
    assert cred["secret"]  # 一次性交付

    # scope 不足 -> 403
    payload["scopes"] = []
    r = client.post("/internal/credentials/db", json=payload, headers=_auth_headers(tok))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "credential_scope_denied"

    # 引用不存在版本 -> 404
    payload["scopes"] = ["db:read"]
    payload["version"] = 99
    r = client.post("/internal/credentials/db", json=payload, headers=_auth_headers(tok))
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "credential_version_not_found"

    # 轮换两次后旧版本 retired -> 409
    vault = gateway._test_vault
    vault.rotate("db", "LOCAL-SECRET-V2")
    vault.rotate("db", "LOCAL-SECRET-V3")
    payload["version"] = 1
    r = client.post("/internal/credentials/db", json=payload, headers=_auth_headers(tok))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "credential_version_retired"


def test_missing_bearer_is_401(client) -> None:
    r = client.post("/internal/authorize", json={"action": "read", "resource": "db"})
    assert r.status_code == 401
