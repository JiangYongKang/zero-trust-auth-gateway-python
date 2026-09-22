"""场景二：默认拒绝、显式拒绝优先、属性缺失单列、热更新与结论可复现。"""
from __future__ import annotations

import json
import pathlib

import pytest

from ztauth.errors import AuthError, DenyReason
from ztauth.policy import Effect, Policy, Rule, evaluate
from ztauth.policy import PolicyStore
from ztauth.sources import JsonPolicySource


def _call(store, **kw):
    p = store.current()
    return evaluate(p, **kw)


_KWARGS = dict(action="read", resource="db-payments")


def test_default_deny_and_explicit_deny_overrides(policy_store):
    # 无任何适用规则 -> 默认拒绝
    d = _call(policy_store, subject={"team": "payments"}, roles=("guest",), **_KWARGS)
    assert d.effect is Effect.DENY and d.matched_rule is None

    # 命中 allow
    d = _call(policy_store, subject={"team": "payments"}, roles=("reader",), **_KWARGS)
    assert d.effect is Effect.ALLOW and d.matched_rule == "p1-allow-payments-reader"

    # 显式 deny（contractor）优先：即使也满足别的 allow 角色
    d = _call(
        policy_store,
        subject={"team": "payments", "employment": "contractor"},
        roles=("reader",), **_KWARGS,
    )
    assert d.effect is Effect.DENY and d.matched_rule == "p2-deny-contractor"
    assert "explicit deny overrides" in d.reason


def test_missing_attribute_is_distinct_from_deny(policy_store):
    # reader 但缺 team 属性 -> 不确定(缺属性)，而非拒绝
    d = _call(policy_store, subject={}, roles=("reader",), **_KWARGS)
    assert d.effect is Effect.INDETERMINATE_MISSING_ATTRIBUTE
    assert d.matched_rule == "p1-allow-payments-reader"
    assert "missing required attribute(s) team" in d.reason


def test_gateway_distinguishes_deny_and_missing(gateway, ring, now):
    from ztauth.tokens import TokenIssuer

    issue = TokenIssuer(ring).issue
    import datetime as dt
    tok_reader = issue(
        "alice", ttl=dt.timedelta(minutes=5), roles=("reader",),
        attrs={"team": "payments"}, now=now,
    )
    tok_noattr = issue("bob", ttl=dt.timedelta(minutes=5), roles=("reader",), now=now)
    tok_guest = issue("g", ttl=dt.timedelta(minutes=5), roles=("guest",),
                      attrs={"team": "payments"}, now=now)

    r = gateway.authorize("rq-ok", tok_reader, "read", "db-payments", now=now)
    assert r.decision.effect is Effect.ALLOW
    assert r.decision.policy_version == 1

    with pytest.raises(AuthError) as ei:
        gateway.authorize("rq-miss", tok_noattr, "read", "db-payments", now=now)
    assert ei.value.reason is DenyReason.POLICY_MISSING_ATTRIBUTE

    with pytest.raises(AuthError) as ei:
        gateway.authorize("rq-deny", tok_guest, "read", "db-payments", now=now)
    assert ei.value.reason is DenyReason.POLICY_DENY


def test_hot_reload_takes_effect_without_restart(gateway_factory, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": 1,
        "rules": [{
            "id": "v1-allow", "effect": "allow", "action": "read",
            "resource": "db-payments", "require": {"team": "payments"},
            "roles": ["reader"],
        }],
    }), encoding="utf-8")
    store = PolicyStore(JsonPolicySource(path))
    gw = gateway_factory(store)

    d1 = evaluate(store.current(), subject={"team": "payments"},
                  roles=("reader",), **_KWARGS)
    assert d1.effect is Effect.ALLOW and d1.policy_version == 1

    # 热更新：v2 改为显式拒绝同一动作
    path.write_text(json.dumps({
        "version": 2,
        "rules": [{
            "id": "v2-deny", "effect": "deny", "action": "read",
            "resource": "db-payments", "require": {"team": "payments"},
            "roles": ["reader"],
        }],
    }), encoding="utf-8")
    new_version = gw.reload_policies()
    assert new_version == 2

    d2 = evaluate(store.current(), subject={"team": "payments"},
                  roles=("reader",), **_KWARGS)
    assert d2.effect is Effect.DENY
    assert d2.policy_version == 2 and d2.matched_rule == "v2-deny"


def test_decision_is_reproducible_with_recorded_version(policy_store):
    """同一输入 + 同一策略版本 => 逐字节相同的结论（版本/依据可事后复现）。"""
    kw = dict(subject={"team": "payments"}, roles=("reader",), **_KWARGS)
    d_a = evaluate(policy_store.current(), **kw)
    d_b = evaluate(policy_store.current(), **kw)
    assert d_a == d_b
    # 用记录下的版本和规则可以离线重建同一判定
    snap = policy_store.current()
    rebuilt = Policy(version=snap.version, rules=snap.rules)
    assert evaluate(rebuilt, **kw) == d_a


def test_policy_file_source_roundtrip(tmp_path):
    path = pathlib.Path(tmp_path) / "p.json"
    path.write_text(json.dumps({
        "version": 7,
        "rules": [
            {"id": "a", "effect": "allow", "action": "x", "resource": "y",
             "require": {"k": "v"}, "roles": ["r"]},
        ],
    }), encoding="utf-8")
    p = JsonPolicySource(path).load()
    assert p.version == 7
    assert p.rules[0] == Rule("a", "allow", "x", "y", {"k": "v"}, ("r",))
