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

批次模式下遇到当前批次没有的 `kid`，行为与原 `KeyRing` 的受控重载对齐，
并在此基础上把"对上游的真实读取次数"收敛到一个**确定上限**：

```
真实 load 次数 <= 构造期 1 次 + 1 + floor(经过时间 / reload_min_interval)
```

该上限只随时间增长，**与未知 kid 的种类数、请求总量、负缓存容量均无关**。
它由三层机制叠加保证：

- **全局 single-flight**：已有一次回源在途时，后续请求（无论 `kid` 相同
  还是互不相同）都等待这一次 `ReleaseSource.load()` 并复用结果——一次
  load 读出的是整批内容，天然覆盖所有 `kid`。大量并发携带同一个未知
  `kid` 时最多真实读取一次；携带大量不同未知 `kid` 时读取次数也不会
  放大到并发量级。
- **回源节流**（`reload_min_interval`，默认 **1.0** 秒，`clock` 可注入
  以便测试）：两次真实回源之间至少间隔一个窗口。窗口内到达的未知 `kid`
  请求直接按 `token_unknown_kid` 结论返回，**不写入负缓存**，因此窗口
  过后再次出现仍会触发真实回源。
- **有界负缓存**（`negative_cache_size`，默认 **256**）：经上游确认不含
  的 `kid` 连同**确认时刻**记入 LRU。条目只在确认后的一个节流窗口内
  有效，过期自动失效——所以上游后来补发的合法密钥不会被陈旧的否定
  结论永久挡住；每次发布新批次也会清空负缓存并重置节流。

**合法密钥更新的发现时延**：新 `kid` 最迟在一个 `reload_min_interval`
之后被真实回源发现；源内容包含该 `kid` 且 `keys_version` 不旧于当前时，
整批内容原子发布为新批次，对后续请求生效。发起回源的那个请求仍固定在
旧批次（旧批次没有该 kid），按 `token_unknown_kid` 结束——请求不跨批。
`keys_version` 更旧的源内容被视为"源尚未更新"，不产生新批次。

**上游失败时的表现**：真实回源抛出的异常会原样传给所有并发等待方
（不会被挂住，也不会被吞成静默的 unknown），网关层映射为既有的
`token_key_reload_unavailable`，与原单项路径结论一致；失败同样占住
节流窗口，窗口内的后续请求按 `token_unknown_kid` 快速失败，窗口过后
自动重试，上游恢复即正常。

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
uv run pytest -v                                # 逐条列出各业务用例与执行结果
uv run pytest tests/test_releases.py -q         # 发布/回退/淘汰/负缓存单元
uv run pytest tests/test_release_gateway.py -q  # 三段同批、在途不换版
uv run pytest tests/test_release_concurrency.py -q  # 高并发交错
uv run pytest tests/test_release_api.py -q      # HTTP 端点与两类 404
uv run pytest tests/test_unknown_kid_read_bound.py -v  # 未知 kid 读取上限专项
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 日志可见发布标识
```

未知 kid 读取上限的最小复现（不依赖测试框架，可直接照做）：

```python
from ztauth.releases import ReleaseManager
from ztauth.sources import MutableReleaseSource
# content 见上文 §2 的构造方式；clock 用列表模拟可推进的单调时钟
src = MutableReleaseSource(content_v1)
t = [1000.0]
mgr = ReleaseManager(src, negative_cache_size=16,
                     reload_min_interval=5.0, clock=lambda: t[0])

rel = mgr.current()
for n in range(1000):                       # 1000 种未知 kid 持续冲击
    mgr.reload_for_unknown_kid(rel, f"ghost-{n}")
assert src.load_count == 2                  # 构造期 1 次 + 窗口内恰好 1 次

t[0] += 5.0                                 # 推进一个节流间隔
for n in range(1000):
    mgr.reload_for_unknown_kid(rel, f"ghost-{n}")
assert src.load_count == 3                  # 每个间隔最多放行 1 次真实读取
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
