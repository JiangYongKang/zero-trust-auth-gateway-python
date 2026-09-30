"""HTTP：发布/回退端点、成功与 403 均带发布标识、两类回退错误可区分。"""
from __future__ import annotations

import datetime as dt

from fastapi.testclient import TestClient

from ztauth.api import create_app
from ztauth.gateway import Gateway
from ztauth.releases import ReleaseManager
from ztauth.sources import MutableReleaseSource
from ztauth.tokens import TokenIssuer
from tests.test_release_gateway import _content, _token  # noqa: PLC2701


def _client(*, max_retained=8):
    src = MutableReleaseSource(_content())
    mgr = ReleaseManager(src, max_retained=max_retained)
    gw = Gateway(released=mgr, clock=lambda: dt.datetime(
        2026, 9, 30, tzinfo=dt.timezone.utc))
    return TestClient(create_app(gw)), gw, src


def test_authorize_and_management_endpoints_roundtrip():
    client, gw, src = _client()
    token = _token(src._content)  # noqa: SLF001

    resp = client.post("/v1/authorize", json={
        "token": token, "action": "read", "resource": "db",
    }, headers={"x-request-id": "api-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["release_id"] == 1
    assert body["policy_version"] == 1

    c2 = _content(kid="k2", key_secret=b"key-v2", policy_v=2,
                  team="billing", cred_secret=b"cred-v2", kv=2)
    src.set_content(c2)
    resp = client.post("/v1/releases/publish")
    assert resp.status_code == 200 and resp.json() == {"release_id": 2}
    assert client.post("/v1/releases/current").json() == {"release_id": 2}

    token2 = _token(c2, team="billing")
    body = client.post("/v1/authorize", json={
        "token": token2, "action": "read", "resource": "db",
    }).json()
    assert body["release_id"] == 2

    # 旧批次令牌：403 且带当前发布标识
    resp = client.post("/v1/authorize", json={
        "token": token, "action": "read", "resource": "db",
    })
    assert resp.status_code == 403
    err = resp.json()
    assert err["error"] == "token_unknown_kid"
    assert err["release_id"] == 2
    assert "key-v1" not in resp.text  # 密钥材料不外泄

    # 回退到 1
    resp = client.post("/v1/releases/rollback", json={"release_id": 1})
    assert resp.status_code == 200 and resp.json() == {"release_id": 1}
    body = client.post("/v1/authorize", json={
        "token": token, "action": "read", "resource": "db",
    }).json()
    assert body["release_id"] == 1


def test_rollback_unknown_and_retired_return_distinct_404():
    client, gw, src = _client(max_retained=2)
    gw.publish(_content(kid="k2", key_secret=b"b", policy_v=2, kv=2))
    gw.publish(_content(kid="k3", key_secret=b"c", policy_v=3, kv=3))

    resp = client.post("/v1/releases/rollback", json={"release_id": 1})
    assert resp.status_code == 404
    assert resp.json()["error"] == "release_retired"

    resp = client.post("/v1/releases/rollback", json={"release_id": 99})
    assert resp.status_code == 404
    assert resp.json()["error"] == "release_never_existed"


def test_legacy_gateway_without_releases_has_no_management_routes(gateway):
    # 原有装配（ring/policies/vault）继续工作，且不挂发布管理端点
    client = TestClient(create_app(gateway))
    ring = gateway._verifier._ring  # noqa: SLF001
    token = TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"team": "payments"},
        now=dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc),
    )
    resp = client.post("/v1/authorize", json={
        "token": token, "action": "read", "resource": "db-payments",
    })
    assert resp.status_code == 200
    assert resp.json()["release_id"] is None
    resp = client.post("/v1/releases/rollback", json={"release_id": 1})
    assert resp.status_code == 404  # 路由不存在
