# 设计说明：一致且可解释的零信任鉴权链路

本文档记录关键不变量、并发模型与判定优先级，供代码审查与事后排障使用。

## 1. 组件与数据流

```
caller (Bearer token)
   │
   ▼
AuthGateway.authorize / get_credential
   │  1. tokens.verify_token ──▶ keyring.verify_key(kid)
   │                                │ 未知 kid → 单飞 reload
   │                                └ 重叠窗口 [not_after, +overlap) 可验签
   │  2. HotReloadPolicyEngine.decide
   │        │ 指纹(mtime/size 或内容哈希)变化 → 原子替换不可变文档
   │        └ evaluate：deny > missing-attr > allow > default-deny
   │  3. CredentialVault.read（仅 get_credential）
   │            策略 allow + scope 覆盖 + 状态/有效期检查
   ▼
AuthResult(allowed, policy_version, basis)  [+ IssuedCredential 一次性交付]
```

## 2. 密钥环并发模型

- 读路径始终基于不可变快照 `KeyringSnapshot`，无锁共享。
- 写路径（reload）由一把锁保护，并用 `threading.Event` 实现 **单飞**：
  - leader 线程执行真实拉取；follower 线程等待同一事件。
  - leader 成功后替换快照并 `set()`；失败时记录错误并 `set()`，
    follower 感知失败但**旧快照保持在位**。
- 首次加载是强约束（无密钥集合则密钥环不可用）；之后任何失败都不降级
  读路径可用性。
- 选签密钥确定性：在严格 active 集合中取 `(not_before, kid)` 最大者。

## 3. 令牌判定顺序（拒绝原因互斥）

`malformed → unknown_kid（含受控重载）→ signature_mismatch → not_yet_valid / expired → revoked`

- 先验签后读时间/撤销字段，伪造令牌无法触达后续分支。
- MAC 使用 `hmac.compare_digest` 恒定时间比较。
- 异常消息即稳定原因码，不回显令牌或密钥。

## 4. 策略判定优先级

对每条与 `(action, resource)` 相关的规则：principal 约束（空集合=不限制）
与 `requires` 属性约束都满足才算"完全匹配"。聚合后按优先级给结论：

1. 任一完全匹配的 **deny** → 拒绝（basis=该规则 id）；
2. 否则存在因缺属性而未能匹配的规则 → `MISSING_ATTRIBUTE`（独立错误）；
3. 否则任一完全匹配的 **allow** → 允许；
4. 否则 → 默认拒绝（basis=`default_deny`）。

> 显式 deny 优先于 missing-attr：安全确定性结论不应被"补一个属性"翻转。

热更新加载失败且已有旧文档时，继续按旧文档服务（无"无策略"窗口）。

## 5. 凭据不变量

- 任意时刻某具名凭据：≤1 个 active、≤1 个 previous，其余 retired。
- 轮换单调推进版本号（max+1），不允许版本回退。
- retired 永不放行；previous 只能显式按版本读取；默认读取恒为 active。
- 双重授权：`AuthzDecision.allow` 且 caller scopes ⊇ 版本 `read_scopes`。
- `IssuedCredential.secret` 是唯一承载明文的对象；禁止进入日志/异常/`AuthResult`。

## 6. 可复现性

结论四元组 `(policy_version, basis, decision, 请求属性)` 自洽：
同一版本策略文档内容固定时，对同一请求的输出逐字节一致；并发热更新期间，
一个请求只可能观察到完整的旧版本或完整的新版本（不可变文档 + 引用替换），
不会读到半更新状态。

## 7. 本地材料

`ztauth/localconfig.py` 提供 `init`（生成 keys/policy/credentials）与
`mint`（本地签发令牌）。密钥为 32 字节随机字节，凭据 secret 为本地随机串，
全部来自 `secrets` 模块，测试与离线演示不依赖任何网络服务。
