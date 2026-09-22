"""本地属性策略：默认拒绝、显式拒绝优先、热更新、版本可复现。

策略文档（JSON）结构::

    {
      "version": 3,
      "rules": [
        {"id": "...", "effect": "allow"|"deny",
         "principal": {"attr": "name", "in": ["..."]},
         "action": "...", "resource": "...", "requires": ["dept"]}
      ]
    }

判定语义：

* 默认 **拒绝**（无规则匹配时 deny，依据 ``default_deny``）。
* **显式拒绝优先于允许**：任一 deny 规则匹配则拒绝，即使存在 allow。
* 命中规则但策略要求的属性在请求中缺失 → 抛
  :class:`PolicyError(MISSING_ATTRIBUTE)`，与"判定为拒绝"明确区分。
* 每次结论附带生成该策略文档的 ``version``，保证事后可复现。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping, Protocol


Effect = Literal["allow", "deny"]
Decision = Literal["allow", "deny"]


@dataclass(frozen=True, slots=True)
class Rule:
    """单条策略规则。"""

    id: str
    effect: Effect
    action: str
    resource: str
    principal_attr: str = "sub"
    principal_in: frozenset[str] = frozenset()
    requires: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """带版本的不可变策略文档。"""

    version: int
    rules: tuple[Rule, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthzRequest:
    """一次授权请求的属性集合。"""

    principal: str
    action: str
    resource: str
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthzDecision:
    """可解释、可复现的判定结论。"""

    decision: Decision
    version: int
    basis: str          # 命中规则 id 或 default_deny
    reason: str         # 人类可读判定依据（不含敏感值）
    matched_rule: str | None = None


class PolicyStore(Protocol):
    """策略来源（本地文件/内存），支持版本化加载。"""

    def load(self) -> PolicyDocument:
        ...


def evaluate(policy: PolicyDocument, req: AuthzRequest) -> AuthzDecision:
    """对单个请求做策略判定。"""
    raise NotImplementedError


class FilePolicyStore:
    """基于本地 JSON 文件的策略存储。"""

    def __init__(self, path: str | Path) -> None:
        raise NotImplementedError

    def load(self) -> PolicyDocument:
        raise NotImplementedError


class HotReloadPolicyEngine:
    """策略热更新引擎：文件变更后下次判定自动使用新版本，无需重启。"""

    def __init__(
        self,
        store: PolicyStore,
        *,
        reload_check: Callable[[], bool] | None = None,
    ) -> None:
        raise NotImplementedError

    @property
    def version(self) -> int:
        raise NotImplementedError

    def current(self) -> PolicyDocument:
        """返回当前策略文档，必要时检查并重载。"""
        raise NotImplementedError

    def decide(self, req: AuthzRequest) -> AuthzDecision:
        """确保最新策略后判定；属性缺失抛 MISSING_ATTRIBUTE。"""
        raise NotImplementedError

    def force_reload(self) -> PolicyDocument:
        raise NotImplementedError


def parse_policy(data: dict | str | bytes) -> PolicyDocument:
    """解析并校验策略文档，非法结构抛 PolicyError(INVALID_POLICY)。"""
    raise NotImplementedError


def dumps_policy(policy: PolicyDocument) -> str:
    """序列化策略文档为 JSON（测试与本地材料生成用）。"""
    raise NotImplementedError
