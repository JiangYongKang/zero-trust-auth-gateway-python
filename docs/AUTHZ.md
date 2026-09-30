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

## 4. 发布批次（Release batching）

当一次上线要同时换密钥、改规则、换凭据版本时，若三者各自生效，会出现同一批
请求一部分按新配置、一部分按旧配置的"半切换"状态。发布批次把这三者绑定为一个
**不可变整体**一起切换，并支持整批回退。

### 4.1 数据模型

- `ReleasePayload(release_id, keys, key_version, policy, credentials)`：一次
  发布的完整内容；`release_id` 唯一且**单调递增**（由发布源分配，从 1 开始）。
- `ReleaseBundle`：被 `ReleaseManager` 采纳后的批次，内含一个只读
  `FrozenKeyRing`、不可变 `Policy` 与凭据快照字典。请求拿到的是 bundle 引用，
  配置再怎么切换都不影响本次请求。
- `ReleaseManager(source, retain=N)`：
  - `publish(...) -> release_id`：原子登记新批次并把"当前指针"切到它；
  - `rollback(release_id)`：把指针切回保留窗口内的历史批次，**无需重启**即对
    后续请求生效；
  - `use_current()`：上下文管理器，进入即 pin 住当时批次，退出才释放。

### 4.2 请求的批次一致性

- 每个请求在开始时通过 `use_current()` pin 住一个 bundle，随后令牌校验、策略
  判定、凭据读取全部使用该 bundle 内的同一份密钥 / 策略 / 凭据，**绝不跨批次
  混用**。切换发生在请求处理期间时，旧请求仍用旧 bundle 判完，新请求才用新批
  次——因此回退/发布中途不会出现"A 批密钥验签 + B 批策略/凭据"。
- 成功与失败结论都继续带可复现的 `policy_version` / `rationale`，并新增
  `release_id`（`AuthzResult.release_id` 与审计 JSON 同名字段）。
- 切换是指针的原子替换：任何请求看到的要么是完整旧批次、要么是完整新批次，
  不存在配置短暂为空导致的误拒。

### 4.3 未知 kid 与受控刷新（按代际限流）

请求遇到当前批次不认识的 `kid` 时，允许触发**一次**对上游发布源的受控检查
（`try_refresh_for_unknown_kid`）：

- 若上游出现更新批次，则整请求**从令牌校验第一步重新开始**，用新 bundle 完整
  判完（而不是只换密钥）。
- **按当前批次代际限流**：对同一个当前 `release_id` 至多真正读取一次上游。
  大量请求持续携带各不相同的不存在 kid，也只会带来"每个当前代际一次"的读取，
  次数随发布代际有界，绝不随请求量无界增长。
- 同一时刻的并发加载由 single-flight 合并：真正重叠的多个线程只有一个真正
  调用源，其余在锁外等待并复用结果（等待不持有锁，不阻塞其他读取）。
- 回退态下（当前指针落后于上游最新），未知 kid **不**自动向前采纳，避免回退
  被意外冲掉；需要显式 `refresh()` 才重新跟随上游。
- 上游源在受控刷新时不可用，报 `token_key_reload_unavailable`，与"确属未知
  kid"（`token_unknown_kid`）区分。

### 4.4 回退与保留 / 淘汰语义

- `rollback(release_id)` 两种拒绝，彼此可区分：
  - `release_id` 非法或高于已知高水位 → `ReleaseNotFound`（**从未存在**，
    HTTP 404 `release_not_found`）；
  - 该批次确实发布过，但已超出保留窗口被淘汰 → `ReleaseExpired`（**已过保留
    期**，HTTP 410 `release_expired`）。
- 保留上限 `retain`（默认 10，构造时可配，必须 ≥ 1）指**内存中同时保留的
  历史批次数**（含当前批次）。
- 淘汰规则确定：超出上限时按发布先后（id 升序，FIFO）淘汰最老批次，但
  **当前批次与仍有在途请求 pin 的批次绝不淘汰**；若候选批次都在使用中，宁可
  暂时超过上限，等 pin 释放后的下一次发布/释放点再回收。

### 4.5 与单项轮换 / 热更新的兼容范围

- **不启用**发布批次（构造 `Gateway` 时不传 `releases`）：一切行为与原来完全
  一致，`AuthzResult.release_id` 为 `None`，审计也不带该字段。
- **启用**后两者可配合：先照旧调用单项能力把各组件改到目标态
  （`KeyRing.reload()` / `PolicyStore.reload()` / `vault.rotate()`），再调用
  `Gateway.publish_batch()`（不带参数即取三者当前快照）把它们**打包成同一
  批次**原子生效。打包发布前，发布视图仍指向上一批次，单项中途态不对外可见。
- 边界：批次内的密钥集 / 策略 / 凭据是发布时刻的不可变快照；发布之后直接改动
  单项组件**不会**回溯修改已发布批次，只能通过再次发布形成新批次。回退只切换
  指针，不重建也不修改各单项组件。

## 5. 审计

每次判定输出一行 JSON：`request_id / subject / action / resource / effect /
policy_version / rationale / release_id`。启用发布批次时 `release_id` 为本次
实际使用的发布标识，未启用时为 `null`。令牌本身、令牌片段与凭据明文一律不记录。
单测中使用 `pytest -o log_cli=true -o log_cli_level=INFO` 可直接查看。

## 6. 本地测试矩阵

| 文件 | 覆盖点 |
| --- | --- |
| `tests/test_key_rotation.py` | 重叠窗口双密钥验签、窗口外拒绝、未知 kid 单次重载、20 并发只拉一次、密钥源故障独立原因、过期/撤销/签名/格式四因可区分 |
| `tests/test_policy_hot_reload.py` | 默认拒绝、deny 优先、缺属性单列、文件改写后热生效、结论可复现 |
| `tests/test_credentials.py` | 最小权限、版本不存在/已失效区分、重叠期语义、过期、日志无明文 |
| `tests/test_concurrent_authz.py` | 混合请求结论稳定、热更新不跨版本脏读、32 并发未知 kid 合并拉取 |
| `tests/test_api_e2e.py` | HTTP 200/403、错误体可区分且不含机密、热更新端点 |
| `tests/test_release_batches.py` | 单调发布 id、批次原子性、回退即时生效、从未存在/已过期可区分、FIFO 淘汰、当前与在途批次不被淘汰 |
| `tests/test_release_concurrency.py` | 发布/回退与 16 线程鉴权交错不混批、32 并发同批加载只读一次源、未知 kid 洪水读取按代际有界、在途请求按开始批次判完 |
| `tests/test_release_compat.py` | 单项路径不回归、单项轮换打包成批、deny 也带 release_id、未知 kid 自动发现新批、源故障独立原因、切换期间无空配置误拒 |
| `tests/test_release_api.py` | 发布/回退端点、响应带 release_id、404 与 410 区分 |
