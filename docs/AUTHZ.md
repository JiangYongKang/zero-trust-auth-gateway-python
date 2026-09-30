# 鉴权 / 授权语义与轮换规则

## 1. 令牌（Authentication）

- 格式：`base64url(header).base64ul(claims).base64url(HMAC-SHA256)`
  - header：`{"alg":"HS256","typ":"ZT1","kid":"..."}`
  - claims：`sub / jti / iat / exp / roles[] / attrs{}`（时间为 epoch 秒，UTC）
- 校验顺序与结论：
  1. 结构非法 → `token_malformed`
  2. 解析 `kid`：
     - 命中且在有效窗口 → 继续
     - 未知 → 触发一次**受控重载**后重查；仍未知 → `token_unknown_kid`；
       重载时密钥源异常 → `token_key_reload_unavailable`
     - 已知但在窗口外（密钥已退役）→ `token_signature_mismatch`
  3. 恒定时间比较签名，不匹配 → `token_signature_mismatch`
  4. `now ≥ exp` → `token_expired`
  5. `jti` 在撤销集合 → `token_revoked`
- 先验签名再看业务状态，避免对未认证令牌泄露过期/撤销信息。

### 密钥轮换

- 密钥带 `not_before/not_after` 半开区间与 `state∈{active,retiring}`。
- **重叠窗口**：窗口相交的新旧密钥同时可用于验签；签发默认取 `not_before`
  最新的 active 密钥。轮换前已流通、用旧密钥签的未过期令牌在重叠期继续有效。
- 并发安全：
  - 密钥集合是不可变快照，整体原子替换；任何读线程看到的要么是完整旧集合、
    要么是完整新集合，不存在"重载到一半短暂失效"。
  - 未知 `kid` 的重载在锁内 double-check：同一时刻只有一个线程调用
    `KeySource.load()`，其余线程等待并复用结果（single-flight），不会重复拉取。
  - 快照版本单调递增，拒绝降级。

## 2. 策略（Authorization）

- 策略 = `version` + 有序 `rules[]`；规则含 `effect / action / resource /
  require(属性相等约束) / roles`。
- 组合算法（deny-overrides 的可解释变体，按规则文件中的确定顺序扫描）：
  1. 仅 `action/resource` 精确相等且角色相交（规则未限定角色则任意）参与；
  2. 某参与规则缺少它 `require` 的属性 → 记录为"缺属性候选"，**不**算拒绝；
  3. 出现约束全部满足的 `deny` → 立即 **DENY**（显式拒绝最高优先）；
  4. 否则存在"缺属性候选" → **INDETERMINATE_MISSING_ATTRIBUTE**（在网关映射为
     `policy_missing_attribute`），与明确拒绝区分；
  5. 否则存在约束满足的 `allow` → **ALLOW**；
  6. 全部不命中 → **默认 DENY**。
- **热更新**：`JsonPolicySource` 每次 `load()` 重新读盘；改写
  `examples/policy.json` 后调用 `POST /v1/policies/reload`
  （或 `PolicyStore.reload()`）立即对后续请求生效，无需重启。
- **可复现**：`Policy` 为不可变对象，每次判定固定当时快照并在 `Decision` 中
  返回 `policy_version`、`matched_rule` 与确定性 `rationale`。事后用同一版本
  策略 + 同一 `(attrs, roles, action, resource)` 可重建完全相同的结论。
- 热更新与并发：正在执行的判定持有旧快照引用直至结束，因此同一请求内的结论
  不可能混用两个版本（有并发测试守护"属性版本与策略版本对齐"不变量）。

## 3. 凭据分发（Credential retrieval）

- 凭据 = `name` + `allowed_roles`（最小权限白名单）+ 有序版本列表；
  每个版本含 `version / secret / state / not_after`。
- 状态机：
  - `current`：当前默认读取版本；
  - `previous`：轮换重叠期的上一版本，可显式按版本号读取；
  - `retired`：已失效，任何引用拒绝（`credential_version_retired`）。
- `rotate(new_secret)`：旧 `current → previous`，旧 `previous → retired`，
  新版本成为 `current`（版本号严格递增）。`retire_previous()` 结束重叠期。
- 读取规则：
  1. 凭据不存在 → `credential_not_found`；
  2. 请求角色与 `allowed_roles` 无交集 → `credential_forbidden`
     （先于版本判定，避免向无权方暴露版本存在性）；
  3. 默认读 `current`；显式 `version=N` 时：不存在 →
     `credential_version_not_found`，处于 `retired`/已过 `not_after` →
     `credential_version_retired`。两个原因彼此可区分。
- 机密保护：`secret` 只出现在授权成功的返回体（base64）中；审计只记录
  `credential v<版本号>`；所有异常文本与日志均经过断言确保不含明文。

## 4. 审计

每次判定输出一行 JSON：`request_id / subject / action / resource / effect /
policy_version / rationale / release_id`。令牌本身、令牌片段与凭据明文一律不
记录。`release_id` 为本次请求实际使用的发布批次标识（见
[RELEASES.md](RELEASES.md)）；未启用发布批次时为 `null`。
单测中使用 `pytest -o log_cli=true -o log_cli_level=INFO` 可直接查看。

## 5. 发布批次

当一次变更需要同时换密钥、改规则、换凭据版本时，使用发布批次把三者作为一个
不可变整体提交，得到单调递增的发布标识；请求三段链路固定同批、可整批回退、
历史批次按确定规则保留淘汰。语义、边界与兼容范围见
[RELEASES.md](RELEASES.md)。

## 6. 本地测试矩阵

| 文件 | 覆盖点 |
| --- | --- |
| `tests/test_key_rotation.py` | 重叠窗口双密钥验签、窗口外拒绝、未知 kid 单次重载、20 并发只拉一次、密钥源故障独立原因、过期/撤销/签名/格式四因可区分 |
| `tests/test_policy_hot_reload.py` | 默认拒绝、deny 优先、缺属性单列、文件改写后热生效、结论可复现 |
| `tests/test_credentials.py` | 最小权限、版本不存在/已失效区分、重叠期语义、过期、日志无明文 |
| `tests/test_concurrent_authz.py` | 混合请求结论稳定、热更新不跨版本脏读、32 并发未知 kid 合并拉取 |
| `tests/test_releases.py` | 单调发布标识、回退 never_existed/retired 区分、最旧优先淘汰、在途保护不提前淘汰、未知 kid 冲击读取上限、负缓存 LRU 边界、与单项轮换正交 |
| `tests/test_release_gateway.py` | 三段同批一致、成功/失败带发布标识、回退中途不换版、网关层两类回退错误 |
| `tests/test_release_concurrency.py` | 发布/回退与 8 路鉴权交错不跨批、高频发布无空窗误拒、同批并发只读取一次 |
| `tests/test_release_api.py` | HTTP 发布/回退/current、403 带批次、两类 404、旧装配无管理端点 |
| `tests/test_api_e2e.py` | HTTP 200/403、错误体可区分且不含机密、热更新端点 |
