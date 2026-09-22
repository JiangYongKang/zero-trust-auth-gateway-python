"""本地策略：版本化、热更新、默认拒绝、显式拒绝优先、属性缺失单列。

组合算法（deny-overrides 的可解释变体）：
1. 仅 action/resource 精确相等、且角色相交（或规则未限定角色）的规则参与判定；
2. 任一参与规则的全部 require 约束满足且 effect=deny -> DENY（最高优先）；
3. 否则，若存在参与规则缺少必要属性 -> INDETERMINATE_MISSING_ATTRIBUTE，
   与"明确拒绝"区分开；
4. 否则，任一规则约束满足且 effect=allow -> ALLOW；
5. 其余一律默认 DENY。
所有结论附带 policy_version 与确定性的 rationale，可事后复现。
"""
from __future__ import annotations

import dataclasses
import enum
import threading
from typing import Protocol


class Effect(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE_MISSING_ATTRIBUTE = "indeterminate_missing_attribute"


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    effect: str  # "allow" | "deny"
    action: str
    resource: str
    # 属性约束：subject.attrs 中必须存在键且值相等；键缺失 -> 属性缺失
    require: dict[str, str] = dataclasses.field(default_factory=dict)
    roles: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Policy:
    version: int
    rules: tuple[Rule, ...]


@dataclasses.dataclass(frozen=True)
class Decision:
    effect: Effect
    policy_version: int
    matched_rule: str | None
    reason: str  # 确定性判定依据，不含令牌/凭据敏感值


class PolicySource(Protocol):
    def load(self) -> Policy:
        ...


class PolicyStore:
    def __init__(self, source: PolicySource) -> None:
        self._source = source
        self._lock = threading.Lock()
        self._policy = source.load()

    def current(self) -> Policy:
        return self._policy  # 不可变对象，引用读即原子

    def reload(self) -> int:
        with self._lock:
            policy = self._source.load()
            if policy.version >= self._policy.version:
                self._policy = policy
            return self._policy.version


def _rule_applies(rule: Rule, roles: tuple[str, ...]) -> bool:
    return not rule.roles or bool(set(rule.roles) & set(roles))


def evaluate(
    policy: Policy,
    *,
    subject: dict[str, str],
    roles: tuple[str, ...],
    action: str,
    resource: str,
) -> Decision:
    v = policy.version
    allow_match: str | None = None
    missing: list[tuple[str, tuple[str, ...]]] = []

    for rule in policy.rules:  # 规则顺序即策略文件中的确定顺序
        if rule.action != action or rule.resource != resource:
            continue
        if not _rule_applies(rule, roles):
            continue
        absent = tuple(k for k in rule.require if k not in subject)
        if absent:
            missing.append((rule.id, absent))
            continue
        if all(subject[k] == v_ for k, v_ in rule.require.items()):
            if rule.effect == "deny":
                return Decision(
                    Effect.DENY, v, rule.id,
                    f"rule {rule.id}: explicit deny overrides (policy v{v})",
                )
            if allow_match is None:
                allow_match = rule.id

    if allow_match is not None:
        return Decision(
            Effect.ALLOW, v, allow_match,
            f"rule {allow_match}: allow matched (policy v{v})",
        )
    if missing:
        rid, keys = missing[0]
        return Decision(
            Effect.INDETERMINATE_MISSING_ATTRIBUTE, v, rid,
            f"rule {rid}: missing required attribute(s) {','.join(keys)} (policy v{v})",
        )
    return Decision(
        Effect.DENY, v, None,
        f"default deny: no applicable rule for {action} {resource} (policy v{v})",
    )
