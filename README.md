# 零信任鉴权与凭据分发网关（Python）

面向**内部服务间调用**的零信任链路：每个请求依次经过

```
签名令牌校验(authn) → 本地策略判定(authz) → 最小权限凭据读取(credential)
```

三段结论都**可区分原因、可复现、可审计**。全部使用本地生成的密钥材料、本地
JSON 策略与内存凭据库即可运行，无外部依赖（仅 FastAPI + pytest）。

## 目录结构

| 模块 | 职责 |
| --- | --- |
| `ztauth/tokens.py` | HMAC-SHA256 紧凑令牌的签发与校验 |
| `ztauth/keys.py` | 密钥集合：重叠窗口轮换、原子快照、未知 kid 受控重载（single-flight） |
| `ztauth/policy.py` | 版本化本地策略：默认拒绝、显式拒绝优先、属性缺失单列 |
| `ztauth/credentials.py` | 版本化凭据：重叠轮换、最小权限、过期/失效语义 |
| `ztauth/releases.py` | 发布批次：密钥/策略/凭据原子整体发布、整批回退、限期保留与确定性淘汰、加载 single-flight |
| `ztauth/gateway.py` | 三段链路门面，统一错误原因与审计，编排发布批次 pin 与受控刷新 |
| `ztauth/audit.py` | 结构化审计（请求标识、策略版本、判定依据） |
| `ztauth/api.py` | FastAPI 端点 `/v1/authorize`、`/v1/policies/reload` |
| `ztauth/sources.py` | 本地密钥源 / JSON 文件策略源 |
| `main.py` | 本地可运行演示装配 |
| `tests/` | 密钥轮换 / 策略热更新 / 凭据 / 并发鉴权 / 端到端 |

## 快速开始

```bash
uv sync
uv run pytest -q                       # 本地验证（46 个用例）
uv run uvicorn main:app --reload       # 启动演示服务
```

签发一个演示令牌并调用：

```python
import datetime as dt
from ztauth.tokens import TokenIssuer
ring = __import__("main").gateway._verifier  # 仅演示取密钥环
token = TokenIssuer(ring).issue(
    "alice", ttl=dt.timedelta(minutes=5),
    roles=("reader",), attrs={"team": "payments"},
)
# POST /v1/authorize  {"token": token, "action": "read",
#                      "resource": "db-payments"}
```

## HTTP

- `POST /v1/authorize`
  - 请求：`{"token", "action", "resource", "credential_version"?: int}`
  - `200`：`{request_id, subject, effect, policy_version, rationale,
    release_id, credential: {name, version, not_after, secret(base64)}}`
  - `403`：`{"error": <可区分原因>, "detail": ...}`（**不含**凭据/令牌内容）
  - 建议头：`X-Request-Id`；缺省时自动生成。
- `POST /v1/policies/reload`：策略热更新，返回新 `policy_version`。
- `POST /v1/releases/publish`：把当前密钥环 / 策略 / 凭据快照打包成一个发布
  批次原子生效，返回 `{"release_id": <单调整数>}`。
- `POST /v1/releases/rollback`：请求 `{"release_id": N}`，整批回退到仍在保留
  窗口内的历史批次：
  - 成功 `200 {"release_id": N}`；
  - 标识从未存在 `404 {"error": "release_not_found"}`；
  - 曾存在但已超保留期 `410 {"error": "release_expired"}`。

## 发布批次（一次上线同时换密钥/规则/凭据）

- **原子整体**：一个批次 = 固定的一组密钥 + 一份策略 + 一份凭据快照，带唯一且
  单调递增的 `release_id`。发布后新请求完整使用同一批次，不跨批次混用；正在
  处理的请求按它开始时 pin 住的批次完整结束，回退/发布不会中途换版。
- **可复现**：成功与失败结论都继续给 `policy_version`/`rationale`，并附带本次
  实际使用的 `release_id`（返回体与审计 JSON 同名）。
- **整批回退**：按 `release_id` 回退，无需重启即对后续请求生效；"从未存在"与
  "已超保留期"分别是 404 / 410。
- **保留与淘汰**：保留最近 `retain` 个批次（`ReleaseManager(source, retain=N)`，
  默认 10，含当前）；超限时按发布先后 FIFO 淘汰，但当前批次和仍有在途请求的
  批次不会被提前淘汰（必要时暂时超容，等请求结束再回收）。
- **并发稳定**：真正重叠的同批上游加载合并为一次读取；大量请求持续携带当前
  批次不存在的 `kid` 时，对上游的读取按"当前批次代际"有界（每代至多一次），
  不随请求量增长。回退态下未知 kid 不会自动向前跳到更新批次。

### 与单项轮换的兼容范围

- 构造 `Gateway` 时**不传** `releases`：完全是原有行为，结论 `release_id` 为
  `null`，密钥轮换 / 策略热更新 / 凭据轮换照常用。
- 启用发布后，推荐上线姿势是"**先各自改到位，再打包发布**"：照旧
  `KeyRing.reload()` / 改写策略后 `POST /v1/policies/reload` /
  `vault.rotate()`，最后 `POST /v1/releases/publish` 把三者合成同一批次。
- 边界：已发布批次是发布时刻的不可变快照；发布后再直接改单项组件不会回溯改变
  旧批次，只能再发一批。回退只切指针，不重建单项组件。

### 本地照抄运行（无需 HTTP）

```python
# uv run python
import datetime as dt
from ztauth.keys import KeyRing, SigningKey
from ztauth.policy import Policy, PolicyStore, Rule
from ztauth.credentials import (
    InMemoryCredentialVault, Credential, CredentialVersion, VersionState,
)
from ztauth.releases import InMemoryReleaseSource, ReleaseManager, ReleasePayload
from ztauth.gateway import Gateway
from ztauth.tokens import TokenIssuer

NOW = dt.datetime.now(dt.timezone.utc)
def key(kid, secret):
    return SigningKey(kid, secret, NOW - dt.timedelta(days=1),
                      NOW + dt.timedelta(days=30), "active")

ring = KeyRing(__import__("ztauth.sources", fromlist=["MutableKeySource"])
               .MutableKeySource([key("k1", b"one")], version=1))
policy = Policy(1, (Rule("r1", "allow", "read", "db",
                         require={"team": "payments"}, roles=("reader",)),))
policies = PolicyStore(type("S", (), {"load": lambda self: policy})())
vault = InMemoryCredentialVault({"db": Credential(
    "db", ("reader",),
    (CredentialVersion(1, b"db-secret-v1", VersionState.CURRENT, None),))})

initial = ReleasePayload(1, *ring.snapshot(), policy, vault.load_all())
gw = Gateway(ring, policies, vault,
             releases=ReleaseManager(InMemoryReleaseSource(initial), retain=10))

tok1 = TokenIssuer(ring).issue("alice", ttl=dt.timedelta(minutes=5),
                               roles=("reader",), attrs={"team": "payments"}, now=NOW)
print(gw.authorize("r1", tok1, "read", "db", now=NOW).release_id)   # 1

# 一次性换密钥、改规则、换凭据版本，打包成批次 2
ring._source.set_keys([key("k2", b"two")], version=2)
ring.reload()
vault.rotate("db", b"db-secret-v2", now=NOW)
rid = gw.publish_batch()                          # 省略参数=取三者当前快照
print(rid, gw.current_release_id())               # 2 2
print(gw.rollback_batch(1))                       # 整批回退 -> 1
```

## 拒绝原因（可区分）

令牌：`token_malformed` / `token_unknown_kid` / `token_key_reload_unavailable` /
`token_signature_mismatch` / `token_expired` / `token_revoked`
授权：`policy_deny`（默认拒绝或显式拒绝）/ `policy_missing_attribute`（缺必要属性）
凭据：`credential_not_found` / `credential_version_not_found` /
`credential_version_retired` / `credential_forbidden`

## 轮换规则速览

- **密钥**：新旧密钥在重叠窗口（`not_before ≤ now < not_after`）内同时可验签；
  默认用最新 `active` 密钥签发。未知 `kid` 触发一次受控重载（并发合并为一次
  拉取），密钥源不可用报 `token_key_reload_unavailable`，窗口外旧密钥的签名不再
  被信任（`token_signature_mismatch`）。
- **策略**：版本号单调递增；`reload` 后新请求按新版本判定，正在处理的请求沿用
  读取时的不可变快照。每次结论都带 `policy_version`。
- **凭据**：`rotate()` 后新版本为 `current`、旧版本降级为 `previous`（重叠期仍
  可显式引用）、更早版本立即 `retired`；`retire_previous()` 结束重叠期。默认读
  当前版本，也可显式引用重叠期旧版本；引用不存在/已失效版本分别报
  `version_not_found` / `version_retired`。

详见 [`docs/AUTHZ.md`](docs/AUTHZ.md)。

## 本地验证

```bash
uv run pytest                      # 全量
uv run pytest tests/test_key_rotation.py -q
uv run pytest tests/test_policy_hot_reload.py -q
uv run pytest tests/test_credentials.py -q
uv run pytest tests/test_concurrent_authz.py -q
uv run pytest tests/test_release_batches.py -q       # 发布/回退/淘汰
uv run pytest tests/test_release_concurrency.py -q   # 并发与容量压力
uv run pytest tests/test_release_compat.py -q        # 与单项轮换兼容
uv run pytest tests/test_release_api.py -q           # 发布/回退 HTTP
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 打印请求标识/发布批次/依据
```

测试日志为单行 JSON：

```json
ztauth_decision {"request_id":"rq-cred","subject":"alice","action":"read",
 "resource":"db-payments","effect":"allow","policy_version":1,
 "rationale":"[release 1] rule p1-...: allow matched (policy v1); credential v1",
 "release_id":1}
```

凭据明文与令牌字符串**绝不会**出现在日志或错误信息中（有专门断言守护）。
