"""本地属性策略：默认拒绝、显式拒绝优先、热更新、版本可复现。

策略文档（JSON）结构示例::

    {
      "version": 3,
      "rules": [
        {"id": "r1", "effect": "allow", "action": "read",
         "resource": "db://orders", "principal_attr": "sub",
         "principal_in": ["alice"], "requires": ["dept"]}
      ]
    }

判定语义（确定性，便于事后复现）
================================

* **默认拒绝**：没有任何规则与 (action, resource) 相关时，结论为
  ``deny``，依据固定为 ``"default_deny"``。
* **显式拒绝优先于允许**：按规则在文档中的顺序评估，只要存在一条匹配的
  deny 规则即拒绝；只有"存在匹配 allow 且不存在任何匹配 deny"才允许。
* **缺少必要属性与拒绝区分**：规则命中其 (action, resource, principal)
  但请求缺少该规则 ``requires`` 列出的属性时，抛
  :class:`PolicyError(MISSING_ATTRIBUTE)`，而不是默默拒绝。
* **版本可复现**：结论 :class:`AuthzDecision` 始终携带所用策略文档的
  ``version`` 与命中规则 id；同一份策略 + 同一请求必得同一结论。

热更新
======
:class:`HotReloadPolicyEngine` 在每次 :meth:`decide` 前检查策略来源的
指纹（如文件 mtime/大小或显式版本号），变化即原子替换不可变文档快照；
正在进行的判定继续使用旧快照，读路径永不出现"无策略"窗口。
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping, Protocol

from ztauth.errors import PolicyError, PolicyReasons

Effect = Literal["allow", "deny"]
Decision = Literal["allow", "deny"]

DEFAULT_DENY_BASIS = "default_deny"


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
    """可解释、可复现的判定结论（不含任何凭据材料）。"""

    decision: Decision
    version: int
    basis: str
    reason: str
    matched_rule: str | None = None


# ---------------------------------------------------------------------- #
# 解析 / 序列化
# ---------------------------------------------------------------------- #
def _invalid(text: str) -> PolicyError:
    return PolicyError(text, reason=PolicyReasons.INVALID_POLICY)


def parse_rule(idx: int, raw: object) -> Rule:
    if not isinstance(raw, dict):
        raise _invalid(f"rule #{idx} must be an object")
    try:
        rid = str(raw["id"])
        effect = str(raw["effect"])
        action = str(raw["action"])
        resource = str(raw["resource"])
    except KeyError as exc:
        raise _invalid(f"rule #{idx} missing field {exc.args[0]!r}") from exc
    if effect not in ("allow", "deny"):
        raise _invalid(f"rule {rid!r} has invalid effect {effect!r}")
    if not rid:
        raise _invalid(f"rule #{idx} has empty id")
    principal_attr = str(raw.get("principal_attr", "sub"))
    principal_in = frozenset(str(v) for v in raw.get("principal_in", ()))
    requires = frozenset(str(v) for v in raw.get("requires", ()))
    if not isinstance(raw.get("principal_in", ()), (list, tuple, set, frozenset)):
        raise _invalid(f"rule {rid!r} principal_in must be a list")
    if not isinstance(raw.get("requires", ()), (list, tuple, set, frozenset)):
        raise _invalid(f"rule {rid!r} requires must be a list")
    return Rule(
        id=rid,
        effect=effect,  # type: ignore[arg-type]
        action=action,
        resource=resource,
        principal_attr=principal_attr,
        principal_in=principal_in,
        requires=requires,
    )


def parse_policy(data: dict | str | bytes) -> PolicyDocument:
    """解析并校验策略文档；非法结构抛 PolicyError(INVALID_POLICY)。"""
    if isinstance(data, (str, bytes)):
        try:
            obj = json.loads(data)
        except json.JSONDecodeError as exc:
            raise _invalid(f"policy is not valid JSON: {exc.msg}") from exc
    else:
        obj = data
    if not isinstance(obj, dict):
        raise _invalid("policy document must be an object")
    if "version" not in obj:
        raise _invalid("policy document missing 'version'")
    try:
        version = int(obj["version"])
    except (TypeError, ValueError) as exc:
        raise _invalid("policy 'version' must be an integer") from exc
    raw_rules = obj.get("rules", [])
    if not isinstance(raw_rules, list):
        raise _invalid("policy 'rules' must be a list")
    rules = tuple(parse_rule(i, r) for i, r in enumerate(raw_rules))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise _invalid("duplicate rule id in policy document")
    return PolicyDocument(version=version, rules=rules)


def dumps_policy(policy: PolicyDocument) -> str:
    """序列化策略文档为规范 JSON（测试与本地材料生成用）。"""
    return json.dumps(
        {
            "version": policy.version,
            "rules": [
                {
                    "id": r.id,
                    "effect": r.effect,
                    "action": r.action,
                    "resource": r.resource,
                    "principal_attr": r.principal_attr,
                    "principal_in": sorted(r.principal_in),
                    "requires": sorted(r.requires),
                }
                for r in policy.rules
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


# ---------------------------------------------------------------------- #
# 判定
# ---------------------------------------------------------------------- #
def evaluate(policy: PolicyDocument, req: AuthzRequest) -> AuthzDecision:
    """对单个请求做确定性策略判定。"""
    matched_allow: Rule | None = None
    matched_deny: Rule | None = None
    missing: set[str] = set()

    for rule in policy.rules:
        if rule.action != req.action or rule.resource != req.resource:
            continue
        # principal 约束：principal_in 为空表示不限制主体
        if rule.principal_in:
            principal_value = req.attributes.get(
                rule.principal_attr,
                req.principal if rule.principal_attr == "sub" else None,
            )
            if principal_value is None or principal_value not in rule.principal_in:
                continue
        # 到这里 action/resource/principal 均命中
        absent = [a for a in rule.requires if a not in req.attributes]
        if absent:
            missing.update(absent)
            continue
        if rule.effect == "deny" and matched_deny is None:
            matched_deny = rule
        elif rule.effect == "allow" and matched_allow is None:
            matched_allow = rule

    # 优先级：显式拒绝 > 属性缺失 > 显式允许 > 默认拒绝。
    # 显式 deny 是确定性安全结论，优先于属性缺失；属性缺失仅在没有
    # 任何完全匹配的 deny 时才作为独立错误抛出，与"拒绝"区分。
    if matched_deny is not None:
        return AuthzDecision(
            decision="deny",
            version=policy.version,
            basis=matched_deny.id,
            reason=f"explicit deny by rule {matched_deny.id}",
            matched_rule=matched_deny.id,
        )
    if missing:
        raise PolicyError(
            "required attributes absent: " + ",".join(sorted(missing)),
            reason=PolicyReasons.MISSING_ATTRIBUTE,
        )
    if matched_allow is not None:
        return AuthzDecision(
            decision="allow",
            version=policy.version,
            basis=matched_allow.id,
            reason=f"explicit allow by rule {matched_allow.id}",
            matched_rule=matched_allow.id,
        )
    return AuthzDecision(
        decision="deny",
        version=policy.version,
        basis=DEFAULT_DENY_BASIS,
        reason="no matching allow rule; default deny",
        matched_rule=None,
    )


# ---------------------------------------------------------------------- #
# 策略来源
# ---------------------------------------------------------------------- #
class PolicyStore(Protocol):
    """策略来源（本地文件/内存），支持版本化加载。"""

    def load(self) -> PolicyDocument:
        ...

    def fingerprint(self) -> str:
        """来源指纹；指纹不变时跳过重载。"""
        ...


class FilePolicyStore:
    """基于本地 JSON 文件的策略存储，指纹取 mtime+size+内容哈希。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def fingerprint(self) -> str:
        st = self.path.stat()
        return f"{int(st.st_mtime_ns)}-{st.st_size}"

    def load(self) -> PolicyDocument:
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise PolicyError(
                f"policy file unreadable: {self.path}",
                reason=PolicyReasons.NO_POLICY_LOADED,
            ) from exc
        return parse_policy(raw)


class InMemoryPolicyStore:
    """内存策略来源：测试与本地演示用，可原子替换策略文档。"""

    def __init__(self, policy: PolicyDocument) -> None:
        self._policy = policy
        self._rev = 0
        self._lock = threading.Lock()

    def replace(self, policy: PolicyDocument) -> None:
        with self._lock:
            self._policy = policy
            self._rev += 1

    def fingerprint(self) -> str:
        with self._lock:
            digest = hashlib.sha256(
                dumps_policy(self._policy).encode("utf-8")
            ).hexdigest()[:16]
            return f"{self._rev}-{digest}"

    def load(self) -> PolicyDocument:
        with self._lock:
            return self._policy


# ---------------------------------------------------------------------- #
# 热更新引擎
# ---------------------------------------------------------------------- #
class HotReloadPolicyEngine:
    """策略热更新引擎：来源变化后下次判定自动使用新版本，无需重启。"""

    def __init__(
        self,
        store: PolicyStore,
        *,
        reload_check: Callable[[], bool] | None = None,
    ) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._doc: PolicyDocument | None = None
        self._fingerprint: str = ""
        self._reload_check = reload_check
        # 首次强加载，保证引擎始终持有一份可用策略
        doc = self._store.load()
        self._doc = doc
        self._fingerprint = self._safe_fp()

    def _safe_fp(self) -> str:
        try:
            return self._store.fingerprint()
        except Exception:
            return self._fingerprint  # 指纹不可用时保持现状，不误重载

    @property
    def version(self) -> int:
        return self.current().version

    def current(self) -> PolicyDocument:
        """返回当前策略文档；若来源指纹变化则原子重载。"""
        if self._reload_check is None or self._reload_check():
            fp = self._safe_fp()
            if fp != self._fingerprint:
                self.force_reload()
        assert self._doc is not None
        return self._doc

    def decide(self, req: AuthzRequest) -> AuthzDecision:
        """确保最新策略后判定；属性缺失抛 MISSING_ATTRIBUTE。"""
        return evaluate(self.current(), req)

    def force_reload(self) -> PolicyDocument:
        """强制重新加载。

        已持有策略时，加载失败保留旧文档继续服务（不出现无策略窗口）；
        首次加载（尚无策略）失败则向上抛出。
        """
        with self._lock:
            try:
                doc = self._store.load()
            except PolicyError:
                if self._doc is None:
                    raise
                return self._doc
            self._doc = doc
            self._fingerprint = self._safe_fp()
            return doc
