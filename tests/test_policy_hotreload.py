"""策略热更新与判定语义测试。

覆盖：默认拒绝、显式拒绝优先于允许、缺少必要属性与拒绝区分、
热更新后无需重启立即生效、结论附带策略版本可复现、坏策略不打挂旧版本。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from ztauth.errors import PolicyError, PolicyReasons
from ztauth.policy import (
    AuthzRequest,
    FilePolicyStore,
    HotReloadPolicyEngine,
    InMemoryPolicyStore,
    PolicyDocument,
    dumps_policy,
    parse_policy,
    Rule,
)


def req(principal: str = "alice", **attrs: str) -> AuthzRequest:
    return AuthzRequest(
        principal=principal, action="read", resource="db", attributes=attrs
    )


POLICY_V1 = PolicyDocument(
    version=1,
    rules=(
        Rule(
            id="allow-eng",
            effect="allow",
            action="read",
            resource="db",
            principal_in=frozenset({"alice"}),
            requires=frozenset({"dept"}),
        ),
        Rule(
            id="deny-bob",
            effect="deny",
            action="read",
            resource="db",
            principal_in=frozenset({"bob"}),
        ),
    ),
)


def test_default_deny_when_no_rule_matches() -> None:
    from ztauth.policy import evaluate

    d = parse_policy({"version": 1, "rules": []})
    out = evaluate(d, req())
    assert out.decision == "deny"
    assert out.basis == "default_deny"
    assert out.version == 1


def test_explicit_deny_takes_precedence_over_allow() -> None:
    from ztauth.policy import evaluate

    policy = PolicyDocument(
        version=7,
        rules=(
            Rule("a1", "allow", "read", "db"),
            Rule("d1", "deny", "read", "db"),
        ),
    )
    out = evaluate(policy, req())
    assert out.decision == "deny"
    assert out.matched_rule == "d1"
    assert out.version == 7


def test_missing_attribute_is_distinct_from_deny() -> None:
    from ztauth.policy import evaluate

    # alice 的 allow 需要 dept，但没给 -> MISSING_ATTRIBUTE，而非 deny
    with pytest.raises(PolicyError) as ei:
        evaluate(POLICY_V1, req("alice"))
    assert ei.value.reason == PolicyReasons.MISSING_ATTRIBUTE

    # bob 有完全匹配的 deny，即使同时缺属性也优先确定性拒绝
    out = evaluate(POLICY_V1, req("bob"))
    assert out.decision == "deny" and out.basis == "deny-bob"


def test_decision_is_reproducible_with_same_version() -> None:
    from ztauth.policy import evaluate

    d1 = evaluate(POLICY_V1, req("alice", dept="eng"))
    d2 = evaluate(POLICY_V1, req("alice", dept="eng"))
    assert d1 == d2
    assert d1.decision == "allow" and d1.version == 1


def test_hot_reload_takes_effect_without_restart() -> None:
    store = InMemoryPolicyStore(POLICY_V1)
    engine = HotReloadPolicyEngine(store)
    assert engine.version == 1
    assert engine.decide(req("alice", dept="eng")).decision == "allow"

    v2 = parse_policy({"version": 2, "rules": [
        {"id": "deny-all", "effect": "deny", "action": "read", "resource": "db"}
    ]})
    store.replace(v2)  # 无需重启
    out = engine.decide(req("alice", dept="eng"))
    assert out.decision == "deny"
    assert out.version == 2 and out.basis == "deny-all"


def test_file_policy_hot_reload_on_mtime_change(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(dumps_policy(POLICY_V1))
    # 确保 mtime 分辨率足够区分两次写入
    os.utime(path, ns=(1, 1_000_000_000))

    store = FilePolicyStore(path)
    engine = HotReloadPolicyEngine(store)
    assert engine.version == 1

    v3 = parse_policy({"version": 3, "rules": []})
    time.sleep(0.01)
    path.write_text(dumps_policy(v3))
    out = engine.decide(req("alice", dept="eng"))
    assert out.version == 3
    assert out.basis == "default_deny"


def test_bad_policy_on_reload_keeps_previous_version(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(dumps_policy(POLICY_V1))
    store = FilePolicyStore(path)
    engine = HotReloadPolicyEngine(store)

    time.sleep(0.01)
    path.write_text("{ this is not valid json")
    # 重载失败但已有旧策略：继续按 v1 服务，不出现无策略窗口
    out = engine.decide(req("alice", dept="eng"))
    assert out.version == 1 and out.decision == "allow"


def test_invalid_policy_document_is_rejected_at_parse() -> None:
    with pytest.raises(PolicyError) as ei:
        parse_policy({"version": "x", "rules": []})
    assert ei.value.reason == PolicyReasons.INVALID_POLICY
    with pytest.raises(PolicyError) as ei:
        parse_policy({"version": 1, "rules": [{"id": "r", "effect": "maybe"}]})
    assert ei.value.reason == PolicyReasons.INVALID_POLICY
