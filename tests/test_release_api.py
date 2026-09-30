"""发布批次的 HTTP 端点：发布、回退、404/410 区分、响应带 release_id。"""
from __future__ import annotations

import datetime as dt

from fastapi.testclient import TestClient

from ztauth.api import create_app
from ztauth.credentials import (
    Credential,
    CredentialVersion,
    InMemoryCredentialVault,
    VersionState,
)
from ztauth.gateway import Gateway
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import Policy, PolicyStore, Rule
from ztauth.releases import InMemoryReleaseSource, ReleaseManager, ReleasePayload
from ztauth.sources import MutableKeySource
from ztauth.tokens import TokenIssuer

NOW = dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc)


def _key(kid, secret):
    return SigningKey(kid, secret, NOW - dt.timedelta(days=1),
                      NOW + dt.timedelta(days=30), "active")


class _Static:
    def __init__(self, p):
        self.p = p

    def load(self):
        return self.p


def _setup(retain=3):
    keys = [_key("k1", b"one")]
    ring = KeyRing(MutableKeySource(keys, version=1))
    policy = Policy(1, (Rule("r1", "allow", "read", "db",
                             require={"v": "1"}, roles=("reader",)),))
    store = PolicyStore(_Static(policy))
    vault = InMemoryCredentialVault({
        "db": Credential("db", ("reader",),
                         (CredentialVersion(1, b"s1", VersionState.CURRENT, None),)),
    })
    initial = ReleasePayload(1, tuple(keys), 1, policy, vault.load_all())
    mgr = ReleaseManager(InMemoryReleaseSource(initial), retain=retain)
    gw = Gateway(ring, store, vault, releases=mgr, clock=lambda: NOW)
    return gw, ring, store, vault, mgr


def _token(ring, v):
    return TokenIssuer(ring).issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"v": str(v)}, now=NOW,
    )


def test_authorize_reports_release_id():
    gw, ring, *_ = _setup()
    client = TestClient(create_app(gw))
    resp = client.post(
        "/v1/authorize",
        json={"token": _token(ring, 1), "action": "read", "resource": "db"},
        headers={"x-request-id": "api-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["release_id"] == 1
    assert body["request_id"] == "api-1"


def test_publish_then_authorize_uses_new_batch():
    gw, ring, store, vault, mgr = _setup()
    new_keys = [_key("k2", b"two")]
    ring._source.set_keys(new_keys, version=2)
    store._policy = Policy(2, (Rule("r2", "allow", "read", "db",
                                    require={"v": "2"}, roles=("reader",)),))
    vault.rotate("db", b"s2", now=NOW)

    # 先把各单项组件切到目标态（密钥 reload、策略已替换、凭据已轮换）
    ring.reload()
    tok2 = _token(ring, 2)

    client = TestClient(create_app(gw))
    resp = client.post("/v1/releases/publish")
    assert resp.status_code == 200
    assert resp.json() == {"release_id": 2}

    body = client.post(
        "/v1/authorize",
        json={"token": tok2, "action": "read", "resource": "db"},
    ).json()
    assert body["release_id"] == 2
    import base64
    assert base64.b64decode(body["credential"]["secret"]) == b"s2"


def test_rollback_endpoint_ok_and_distinct_errors():
    gw, ring, store, vault, mgr = _setup(retain=2)
    # 发布 2、3，使 1 超出保留窗口被淘汰
    for rid, kv in ((2, b"two"), (3, b"three")):
        gw.publish_batch(
            keys=(_key(f"k{rid}", kv),), key_version=rid,
            policy=Policy(rid, (Rule(f"r{rid}", "allow", "read", "db",
                                     require={"v": str(rid)}, roles=("reader",)),)),
            credentials={
                "db": Credential("db", ("reader",),
                                 (CredentialVersion(rid, f"s{rid}".encode(),
                                                    VersionState.CURRENT, None),)),
            },
        )
    client = TestClient(create_app(gw))

    # 回退到仍保留的 2
    ok = client.post("/v1/releases/rollback", json={"release_id": 2})
    assert ok.status_code == 200 and ok.json() == {"release_id": 2}

    # 从未存在 -> 404 release_not_found
    nf = client.post("/v1/releases/rollback", json={"release_id": 99})
    assert nf.status_code == 404
    assert nf.json()["error"] == "release_not_found"

    # 存在过但已淘汰 -> 410 release_expired
    ex = client.post("/v1/releases/rollback", json={"release_id": 1})
    assert ex.status_code == 410
    assert ex.json()["error"] == "release_expired"
