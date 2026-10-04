# 发布批次（Release Batches）：同批生效、整批回退

一次上线往往要**同时**换签名密钥、改策略、换凭据版本。若三者各自生效，同一批
请求就会出现"一半按新配置、一半按旧配置"的错配，出问题也无法整批回退。
发布批次在原有三个单项能力之上再加一层协调：

```
publish(密钥集合 + 策略 + 凭据库) -> release_id（唯一、单调递增）
authorize(...)                   -> 固定使用开始时的 release_id，三段同批
rollback(release_id)             -> 立即切回保留期内的历史批次
```

## 1. 数据模型

- `ReleaseContent`：一次发布的**完整**内容，三个字段缺一不可：
  - `keys: tuple[SigningKey, ...]`（密钥集合）
  - `policy: Policy`（版本化策略）
  - `credentials: dict[str, Credential]`（凭据库快照）
  - `keys_version: int`：密钥集合的单调版本号，用于受控回源时识别"上游是否
    真的更新了"（见 §5）。
- `Release`：`id + content` 的**不可变**对象。一旦发布内容永不变更。
- `ReleaseManager`：持有"当前批次指针 + 历史批次保留表 + 在途引用计数"。

## 2. 发布与同批一致

```python
import datetime as dt
from ztauth.gateway import Gateway
from ztauth.releases import ReleaseContent, ReleaseManager
from ztauth.sources import MutableReleaseSource

content_v1 = ReleaseContent(keys=..., policy=..., credentials=..., keys_version=1)
source = MutableReleaseSource(content_v1)
manager = ReleaseManager(source, max_retained=8)  # 构造期读出的内容即 release 1
gateway = Gateway(released=manager)

rid = gateway.authorize("rq-1", token, "read", "db").release_id
assert rid == 1

rid2 = gateway.publish(ReleaseContent(..., keys_version=2))  # -> 2
assert gateway.current_release_id() == 2
```

- 发布标识从 **1** 开始，每次 `publish` 严格 +1，绝不复用、绝不乱序。
- 发布在锁内整体提交：读线程拿到的永远是**一份完整批次**，不会出现"密钥已新、
  策略仍旧"的中间态，也不会出现配置短暂为空导致的误拒。
- 每次 `authorize` 在入口 `acquire()` 固定当前批次，令牌验签、策略判定、凭据
  读取全部取自同一个 `Release` 对象。成功结果 `AuthzResult.release_id` 给出
  实际使用的发布标识；失败时抛出的 `AuthError.release_id` 同样带标识。
- HTTP 层：`200` 与 `403` 响应体都含 `release_id`；审计日志每条记录含
  `"release_id": N`（未启用批次时为 `null`）。

## 3. 回退（rollback）

```python
gateway.rollback(1)          # 切回 release 1，无需重启，对后续请求立即生效
```

- 回退只移动"当前批次指针"。**正在处理中的请求**在入口已 `acquire()` 固定旧
  批次并持有引用直到请求结束，因此回退不会把它中途换到新版本——它按开始时
  看到的批次完整结束；回退后新进入的请求才使用目标批次。
- 两种非法标识明确区分（`ReleaseError.kind` / HTTP 404 的 `error`）：

| 情况 | kind | HTTP error |
| --- | --- | --- |
| 标识从未被分配过（如 999） | `never_existed` | `release_never_existed` |
| 曾存在但已超出保留期被淘汰 | `retired` | `release_retired` |

- 可以在任意保留批次之间来回切换（20→1→15→30），回退本身不分配新标识，
  也不改变历史批次的内容。

## 4. 保留与淘汰（retention & eviction）

- `max_retained`（默认 **8**，必须 ≥ 1）是保留历史批次数量的明确上限。
- **淘汰规则（确定的）**：当保留数量超过上限时，按发布标识**升序（最旧优先）**
  淘汰，且永远跳过两类批次：
  1. 当前批次（即使它最旧）；
  2. 仍有正在处理请求引用的批次（引用计数 > 0）。
- 因此容量可能**临时超限**：若所有旧批次都仍在途，宁可多保留也不提前淘汰；
  等在途请求结束（`acquire()` 退出）或下一次发布时补做淘汰。
- 被淘汰批次的标识仍落在历史区间内，回退时报 `retired`，不会误报成
  `never_existed`。

```python
manager = ReleaseManager(source, max_retained=3)
manager.retained_ids()   # (1, 2, 3)
manager.in_flight(rid)   # 某批次当前在途请求数
```

## 5. 未知 kid 的受控回源（兼容原有单次重载语义）

批次模式下遇到当前批次没有的 `kid`，行为与原 `KeyRing` 的受控重载对齐：

- **全局 single-flight**：同一时刻整个管理器最多只有**一次**真正的
  `ReleaseSource.load()`。并发请求无论携带的 `kid` 是否相同，都等待同一次
  读取并复用同一结果；读取失败时所有等待方得到**同一个异常**（不会被挂住），
  经网关映射为既有的 `token_key_reload_unavailable`，与单项路径结论一致。
- 源内容包含该 `kid` 且 `keys_version` 不旧于当前：整批内容原子发布为新批次；
  但**发起回源的那个请求仍固定在旧批次**（旧批次没有该 kid），按
  `token_unknown_kid` 结束——请求不跨批；后续新请求自然使用新批次。
- `keys_version` 更旧的源内容被视为"源尚未更新"，不产生新批次。
- 源不可用：映射为既有的 `token_key_reload_unavailable`。

### 5.1 读取次数上限：时间闸门负缓存

> 旧实现按 `kid` 记有界 LRU 负缓存：未知 `kid` 种类超过容量后，被淘汰的
> `kid` 再次出现会重新回源——压测中"种类足够多且不断变化"的未知标识可把
> 上游真实读取打到无界（种类数 × 轮换轮次）。现改为**时间闸门**：

- 每次真实回源（无论结果）后关闭闸门 `reload_cooldown` 秒（构造参数，
  默认 **1.0**，时钟可注入便于测试）。闸门期内**任何**未知 `kid` 都不再
  回源，直接按当前批次判定。
- **确定上限**：上游内容不变时，任意时长 `T` 内真实读取次数
  **≤ 2 + ⌊T / reload_cooldown⌋**（含构造期的首次读取；每个冷却窗口至多
  一次）。该上限与未知 `kid` 的种类数、请求总量、并发度均无关：种类从
  几十放大到几千、同一批标识反复轮换、64 路并发，读取次数都稳定在
  "每个冷却窗口一次"附近。
- **不漏掉合法更新**：回源读到含新 `kid` 的整批会原子发布新批次并**复位
  闸门**；显式 `publish` 同样复位。上游密钥更新最迟在冷却结束后的下一次
  未知 `kid` 请求中被发现（有界陈旧 ≤ `reload_cooldown`），随后立即对
  后续请求生效。
- **上游失败时的表现**：失败的一次回源同样关闭闸门并**缓存该异常**。并发
  等待方与闸门期内的后续请求都立即得到同一个失败（网关侧
  `token_key_reload_unavailable`），不会反复打到已故障的上游；冷却结束后
  的下一个请求才允许重试一次。

```python
manager = ReleaseManager(source, max_retained=8,
                         reload_cooldown=1.0)   # 未知 kid 回源冷却（秒）
```

### 5.2 本地可复现验证（读取上限）

```bash
# 8 个场景：种类远超单批规模 / 种类数扫描 / 反复轮换 / 并发同标识 /
# 并发不同标识 / 合法更新及时发现 / 上游失败 / 上限公式
uv run pytest tests/test_unknown_kid_read_bound.py -v \
    -o log_cli=true -o log_cli_level=INFO
```

日志中每个场景都会打印"标识种类数 / 并发数 / 真实读取次数 / 上限"，例如：

```
场景2 种类数扫描: kids=2048 真实读取=2 上限=2
场景8 上限公式: 请求=5000 标识种类=5000 真实读取=11 公式上限=12
```

也可以交互式复现（种类数、轮次可调，`load_count` 即上游真实读取次数）：

```python
from ztauth.releases import ReleaseManager
from ztauth.sources import MutableReleaseSource
# ... 构造 ReleaseContent（见 §2）...
src = MutableReleaseSource(content_v1)
mgr = ReleaseManager(src, reload_cooldown=1.0)
for _ in range(3):                            # 同一批标识反复轮换
    for i in range(1000):                     # 1000 种未知 kid
        mgr.reload_for_unknown_kid(mgr.current(), f"bogus-{i}")
assert src.load_count <= 3                    # 远小于 3000，且不再增长
```

## 6. 与原有单项轮换/热更新的兼容范围

| 能力 | 未启用批次（原路径） | 启用批次（ReleaseManager） |
| --- | --- | --- |
| 密钥重叠窗口轮换、未知 kid 单次重载 | `KeyRing` 原样 | 由批次密钥视图 + 管理器回源承担，拒绝原因不变 |
| 策略热更新 `POST /v1/policies/reload` | 原样支持 | 返回当前批次的策略版本；换版请用 publish |
| 凭据 `rotate/retire_previous`、显式版本引用 | 原样支持 | 内容在批次内冻结；轮换通过发布新批次完成 |
| 审计 `request_id/policy_version/rationale` | 原样，`release_id=null` | 额外带 `release_id` |
| 构造方式 | `Gateway(ring, policies, vault)` | `Gateway(released=manager)` |

两条路径互不共享可变状态：原有 `KeyRing/PolicyStore/InMemoryCredentialVault`
仍可独立使用（既有全部测试不回归）。批次内的凭据版本引用语义（current/
previous/retired、过期判定）与原来完全一致，因为读取的是同一份 `Credential`
快照结构。

边界行为：

- 没有配置 ReleaseManager 时，管理端点（publish/rollback/current）不存在，
  授权响应 `release_id` 为 `null`。
- `Gateway` 必须二选一提供配置来源：三件套或 ReleaseManager，否则构造即报错。
- 发布内容是"整体替换"语义：新批次未包含的凭据/密钥，在该批次下即不存在，
  按既有的 `credential_not_found` / `token_unknown_kid` 判定。
- 发布/回退的临界区只做指针与字典操作（无 I/O、无鉴权计算），读路径
  `current()` 为无锁原子引用读，因此读写互不长时间阻塞。

## 7. HTTP 端点

| 端点 | 说明 |
| --- | --- |
| `POST /v1/authorize` | 同前；响应增加 `release_id` |
| `POST /v1/releases/publish` | 从已配置发布源读出最新整批并发布，返回 `{release_id}` |
| `POST /v1/releases/current` | 返回当前 `{release_id}` |
| `POST /v1/releases/rollback` | 请求体 `{"release_id": N}`，返回生效标识 |

## 8. 本地可复现验证

```bash
uv sync
uv run pytest                                   # 全量（含发布批次新增用例）
uv run pytest tests/test_releases.py -q         # 发布/回退/淘汰/回源闸门单元
uv run pytest tests/test_release_gateway.py -q  # 三段同批、在途不换版
uv run pytest tests/test_release_concurrency.py -q  # 高并发交错
uv run pytest tests/test_release_api.py -q      # HTTP 端点与两类 404
uv run pytest tests/test_unknown_kid_read_bound.py -v \
    -o log_cli=true -o log_cli_level=INFO       # 未知 kid 读取上限（8 场景）
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 日志可见发布标识
```

审计日志示例（成功/失败都带 `release_id`）：

```json
ztauth_decision {"request_id":"rq-1","subject":"alice","action":"read",
 "resource":"db","effect":"allow","policy_version":1,
 "rationale":"rule p1: allow matched (policy v1); credential v1","release_id":1}
ztauth_decision {"request_id":"rq-x","subject":"<unauthenticated>","action":"read",
 "resource":"db","effect":"deny","policy_version":null,
 "rationale":"authn_failed:token_unknown_kid:kid=k1","release_id":2}
```

交互式冒烟（启动演示服务后另开终端）：

```bash
uv run uvicorn main:app --reload
curl -s -XPOST localhost:8000/v1/releases/current     # {"release_id":1}
curl -s -XPOST localhost:8000/v1/releases/rollback \
     -H 'content-type: application/json' -d '{"release_id":1}'
```
