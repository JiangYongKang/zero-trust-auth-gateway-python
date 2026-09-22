# 零信任鉴权与凭据分发网关（内部调用）

一个面向 **内部服务间调用** 的零信任鉴权网关：每次调用都需出示签名令牌，
经过「令牌校验 → 本地策略判定 → 最小权限凭据读取」三段链路，给出
**一致、可解释、可复现** 的结论。所有密钥与策略材料均在本地生成，
**无需任何外部 KMS / 网络依赖** 即可运行与测试。

- Python 3.14 · FastAPI · 仅标准库加密原语（HMAC-SHA256）
- 模块：`ztauth/`（`keyring` / `tokens` / `policy` / `credentials` / `engine` / `logging_utils`）

---

## 1. 快速开始（本地自验）

```bash
uv sync --group dev

# 1) 生成本地材料（密钥/策略/凭据），全部使用进程本地熵
uv run python -m ztauth.localconfig init ./local-material

# 2) 启动服务
uv run uvicorn main:app --reload

# 3) 用本地密钥签发一个 alice 的令牌
TOKEN=$(uv run python -m ztauth.localconfig mint ./local-material \
        --sub alice --scope db:read --attr dept=eng | head -1)

# 4) 调用授权接口
curl -s -X POST http://127.0.0.1:8000/internal/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"read","resource":"db","attributes":{"dept":"eng"}}'
```

成功响应（注意 `policy_version` 与 `basis`，可用于事后复现）：

```json
{"request_id":"req-...","allowed":true,"policy_version":1,
 "basis":"allow-alice-read-db","detail":"explicit allow by rule allow-alice-read-db"}
```

运行全部单测（控制台会打印每次判定的 request_id / policy_version / basis）：

```bash
uv run pytest -s
```

---

## 2. 鉴权语义（Authentication）

令牌为自包含的紧凑字符串：`base64url(payload).base64url(HMAC_SHA256)`，
payload 内含 `kid / sub / jti / iat / nbf / exp / scopes / attrs`。

校验顺序固定，**拒绝原因彼此可区分**：

| 场景 | 原因码 `reason` | HTTP |
|---|---|---|
| 结构无法解析 | `token_malformed` | 401 |
| 未知密钥标识（受控重载后仍未知/超出重叠窗） | `token_unknown_kid` | 401 |
| 签名不匹配（恒定时间比较） | `token_signature_mismatch` | 401 |
| 尚未生效 `nbf` / 已过期 `exp` | `token_not_yet_valid` / `token_expired` | 401 |
| 已在撤销清单（按 `jti`） | `token_revoked` | 401 |
| 策略判定缺少必要属性（**区别于拒绝**） | `policy_missing_attribute` | 422 |

### 密钥轮换规则

- 每个密钥带激活窗口 `[not_before, not_after)`；新密钥 `not_before`
  起即可用于签发与验签。
- **确定的重叠窗口**：旧密钥到达 `not_after` 后，在配置的
  `overlap_seconds` 宽限期内（`[not_after, not_after+overlap)`）**仅可验签**，
  不再用于签发。因此轮换边界两侧都无歧义，旧令牌平滑过渡。
- **未知 kid 触发受控重载**：遇到未知 `kid` 不会立即判失败，而是触发一次
  reload，仍未知才拒绝。
- **单飞（single-flight）重载**：高并发下多个未知 kid 只触发一次真实拉取，
  其余请求等待同一结果；reload 失败时继续使用上一个良好快照，
  **不出现短暂失效**。

---

## 3. 授权语义（Authorization）

策略为带 `version` 的本地 JSON 文档，热更新后**无需重启**即生效
（基于文件 `mtime+size` 指纹，下次判定自动加载；坏文档保留旧版本服务）。

判定规则：

1. **默认拒绝**：无规则匹配 → `deny`，依据 `default_deny`。
2. **显式拒绝优先于允许**：只要存在一条完全匹配的 `deny` 规则即拒绝，
   即使同时存在匹配的 `allow`。
3. **缺属性 ≠ 拒绝**：规则要求的 `requires` 属性缺失时返回
   `policy_missing_attribute`（HTTP 422），与确定性拒绝（403 语义）区分；
   但若同时存在完全匹配的 deny，则安全优先，直接拒绝。
4. **主体以令牌为准**：请求体自报的 principal 被忽略，杜绝身份伪造提权。
5. **可复现**：每次结论都带 `policy_version` 与命中规则 `basis`；
   同一版本策略对同一请求必得同一结论。

策略示例见 `local-material/policy.json`（由 `init` 生成）：

```json
{"version":1,"rules":[
  {"id":"allow-alice-read-db","effect":"allow","action":"read","resource":"db",
   "principal_attr":"sub","principal_in":["alice"],"requires":["dept"]},
  {"id":"deny-bob-read-db","effect":"deny","action":"read","resource":"db",
   "principal_attr":"sub","principal_in":["bob"]}]}
```

---

## 4. 凭据读取与轮换（Credentials）

凭据按 `名称 + 版本号` 管理，版本状态机：

```
active ──rotate──▶ previous ──(retire / 被下一轮挤出)──▶ retired
```

- `rotate` 时新版本成为 **active**，旧 active 变为 **previous**（重叠窗口），
  旧 previous 立即变为 **retired**。任意时刻至多一个 active、一个 previous。
- 默认读取解析到 active；**重叠期内允许显式指定版本号读取 previous**，
  供在途调用收尾。
- `retired` 版本即使被显式引用也拒绝（防止重复使用已失效版本）。
- 每个版本带 `[not_before, not_after)` 有效期与 `read_scopes` 最小权限集合。

读取必须同时满足（任一不满足即以可区分原因拒绝）：

| 检查 | 失败原因码 | HTTP |
|---|---|---|
| 策略未授权 | `credential_scope_denied` | 403 |
| 调用方 scope 未覆盖 `read_scopes` | `credential_scope_denied` | 403 |
| 凭据不存在 | `credential_not_found` | 404 |
| 显式版本不存在 | `credential_version_not_found` | 404 |
| 引用已失效（retired/超窗）版本 | `credential_version_retired` | 409 |
| active 版本超出有效期 | `credential_not_readable` | 409 |

**零泄露**：凭据明文只在 `POST /internal/credentials/{name}` 的一次性响应中
交付；所有异常消息、日志、判定结论只包含凭据 *名称* 与 *版本号*，
日志组件对 `token/secret/key/...` 与令牌形态自动脱敏。

---

## 5. HTTP 接口

| 方法 & 路径 | 说明 |
|---|---|
| `GET /healthz` | 健康检查 |
| `POST /internal/verify` | 仅校验令牌，返回主体/kid/作用域 |
| `POST /internal/authorize` | 校验 + 策略判定，返回 allowed/version/basis |
| `POST /internal/credentials/{name}` | 完整链路并一次性交付凭据明文 |

所有接口取 `Authorization: Bearer <token>`，可选 `X-Request-Id`。

---

## 6. 可观测性与本地测试

每条判定日志单行输出，固定携带 `request_id`、`policy_version` 与判定依据：

```
... request_id=req-chain-1 policy_version=1 authorize decision
    principal=alice action=read resource=db allowed=True
    policy_version=1 basis=allow-alice-db ...
```

测试分三类场景（另加令牌原因、凭据、接口测试）：

- `tests/test_key_rotation.py`：重叠窗口、受控重载、单飞、失败保留快照
- `tests/test_policy_hotreload.py`：默认拒绝/显式拒绝优先/缺属性/热更新/版本可复现
- `tests/test_concurrent_auth.py`：轮换中并发零失败、热更新版本一致、单飞
- `tests/test_token_reasons.py` / `test_credentials.py` / `test_engine.py` / `test_api.py`

更详细的设计与不变量见 [`docs/design.md`](docs/design.md)。
