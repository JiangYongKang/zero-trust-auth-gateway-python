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
| `ztauth/gateway.py` | 三段链路门面，统一错误原因与审计 |
| `ztauth/audit.py` | 结构化审计（请求标识、策略版本、判定依据） |
| `ztauth/api.py` | FastAPI 端点 `/v1/authorize`、`/v1/policies/reload` |
| `ztauth/sources.py` | 本地密钥源 / JSON 文件策略源 |
| `main.py` | 本地可运行演示装配 |
| `tests/` | 密钥轮换 / 策略热更新 / 凭据 / 并发鉴权 / 端到端 |

## 快速开始

```bash
uv sync
uv run pytest -q                       # 本地验证（23 个用例）
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
    credential: {name, version, not_after, secret(base64)}}`
  - `403`：`{"error": <可区分原因>, "detail": ...}`（**不含**凭据/令牌内容）
  - 建议头：`X-Request-Id`；缺省时自动生成。
- `POST /v1/policies/reload`：策略热更新，返回新 `policy_version`。

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
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 打印请求标识/策略版本/依据
```

测试日志为单行 JSON：

```json
ztauth_decision {"request_id":"rq-cred","subject":"alice","action":"read",
 "resource":"db-payments","effect":"allow","policy_version":1,
 "rationale":"rule p1-...: allow matched (policy v1); credential v1"}
```

凭据明文与令牌字符串**绝不会**出现在日志或错误信息中（有专门断言守护）。
