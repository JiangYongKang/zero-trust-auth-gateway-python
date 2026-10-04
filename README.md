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
| `ztauth/releases.py` | 发布批次：整批发布/回退、在途固定、保留淘汰、未知 kid 受控回源 |
| `ztauth/gateway.py` | 三段链路门面，统一错误原因与审计（支持发布批次） |
| `ztauth/audit.py` | 结构化审计（请求标识、策略版本、发布批次、判定依据） |
| `ztauth/api.py` | FastAPI 端点 `/v1/authorize`、`/v1/policies/reload`、`/v1/releases/*` |
| `ztauth/sources.py` | 本地密钥源 / JSON 文件策略源 / 内存发布批次源 |
| `main.py` | 本地可运行演示装配（默认运行在发布批次模式） |
| `tests/` | 密钥轮换 / 策略热更新 / 凭据 / 并发鉴权 / 发布批次 / 端到端 |

## 快速开始

```bash
uv sync
uv run pytest -q                       # 本地验证（55 个用例）
uv run uvicorn main:app --reload       # 启动演示服务（发布批次模式）
```

签发一个演示令牌并调用（演示服务运行在发布批次模式，从当前批次取密钥）：

```python
import datetime as dt
from ztauth.keys import KeyRing
from ztauth.tokens import TokenIssuer
import main

rel = main.gateway.current_release_id()
content = main.gateway._releases.current().content          # 当前发布批次
ring = KeyRing(type("S", (), {                               # 用批次密钥构造签发环
    "load": lambda self: (list(content.keys), content.keys_version),
})())
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
  - `200`：`{request_id, subject, effect, policy_version, release_id, rationale,
    credential: {name, version, not_after, secret(base64)}}`
  - `403`：`{"error": <可区分原因>, "detail": ..., "release_id": ...}`
    （**不含**凭据/令牌内容；未启用批次时 `release_id` 为 `null`）
  - 建议头：`X-Request-Id`；缺省时自动生成。
- `POST /v1/policies/reload`：策略热更新（原有单项路径），返回新 `policy_version`。
- `POST /v1/releases/publish`：从已配置发布源读取最新整批并发布，返回
  `{release_id}`；`POST /v1/releases/current` 查询当前批次；
  `POST /v1/releases/rollback`（`{"release_id": N}`）回退。

## 发布批次（整批生效、整批回退）

一次上线同时换密钥、改规则、换凭据版本时，用 `ReleaseManager` 把三者作为
**一个不可变批次**提交，得到唯一且单调递增的发布标识；新请求完整使用同一批次，
成功与失败都返回/记录实际使用的 `release_id`。回退按标识切回保留期内批次，
`never_existed`（从未存在）与 `retired`（已过保留期）两种错误明确可区分；
正在处理的请求按开始时固定的批次完整结束，不被中途换版。

- 历史批次保留上限可配置（`max_retained`，默认 8）；超限按**发布标识最旧优先**
  淘汰，但当前批次与仍有在途请求的批次不会被提前淘汰（容量可能临时超限）。
- 未知 kid 受控回源：全局 single-flight（并发同/不同标识都合并为一次真实
  上游读取）+ 回源节流（`reload_min_interval`，默认 1s）+ 有界 LRU 负缓存
  （条目带确认时刻、过期自动失效）。未知标识持续冲击下真实读取次数收敛到
  确定上限 `1 + 经过时间 / reload_min_interval`，与标识种类数和请求总量
  无关；合法新密钥最迟一个间隔后被发现；每次发布清空负缓存并重置节流。
- 与原有单项能力（密钥重叠轮换、策略热更新、凭据 rotate/retire）**互不影响**：
  仍可直接使用 `Gateway(ring, policies, vault)`；批次模式构造为
  `Gateway(released=manager)`，原有 23 个用例全部保留。

详见 [`docs/RELEASES.md`](docs/RELEASES.md)。

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

详见 [`docs/AUTHZ.md`](docs/AUTHZ.md)；发布批次的完整语义与边界见
[`docs/RELEASES.md`](docs/RELEASES.md)。

## 本地验证

```bash
uv run pytest                      # 全量
uv run pytest -v                   # 逐条列出各业务用例与执行结果
uv run pytest tests/test_key_rotation.py -q
uv run pytest tests/test_policy_hot_reload.py -q
uv run pytest tests/test_credentials.py -q
uv run pytest tests/test_concurrent_authz.py -q
uv run pytest tests/test_releases.py -q             # 发布/回退/淘汰/负缓存
uv run pytest tests/test_release_gateway.py -q      # 三段同批、在途不换版
uv run pytest tests/test_release_concurrency.py -q  # 发布回退×并发鉴权交错
uv run pytest tests/test_release_api.py -q          # HTTP 发布/回退/两类404
uv run pytest tests/test_unknown_kid_read_bound.py -v  # 未知 kid 读取上限专项
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 打印请求标识/批次/版本/依据
```

测试日志为单行 JSON：

```json
ztauth_decision {"request_id":"rq-cred","subject":"alice","action":"read",
 "resource":"db-payments","effect":"allow","policy_version":1,
 "rationale":"rule p1-...: allow matched (policy v1); credential v1",
 "release_id":1}
```

凭据明文与令牌字符串**绝不会**出现在日志或错误信息中（有专门断言守护）。
