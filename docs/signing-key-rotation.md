# 签名密钥轮换操作手册

本手册描述当前单一 issuer 的密钥操作流程，依据 [identity 密钥实现](../src/oidc/keys.rs)、[管理原操作事务](../src/admin_operations.rs)、[平台管理代理](../../saas-plateform/backend/src/oidc/remote_admin.rs)及[当前结构基线](../../saas-plateform/backend/migrations/0001_init.sql)。它是操作说明，不是测试通过或生产演练的证明；实际执行结果、源码与二进制摘要、UTC 时间、逐例结论和清理记录应另行归档。

## 1. 权威、入口与操作身份

所有 identity 实例必须连接同一权威数据库、使用相同且完全匹配的 HTTPS `OIDC_ISSUER`。`auth_provider_settings` 保存唯一 issuer，`auth_signing_keys` 保存公钥与生命周期，`identity_auth_command_receipts` 保存原管理操作结果。这些现有名称仍被 canonical 协议使用，不要另建平行表或 issuer。

公开发现文档的 `jwks_uri` 是 `GET /oauth/jwks`。该入口只返回尚未退役、尚未吊销的公钥，包括已经发布但尚未激活的密钥。返回字段为 `kty=RSA`、`use=sig`、`alg=RS256`、`kid`、`n`、`e`，不含私钥。使用受信 CA 校验实际 issuer 的证书，不以跳过 TLS 校验、替换 issuer 或旧 `/oidc/*` 路径处理故障。

日常操作从平台当前 canonical 员工 BFF 发起：

| 操作 | 平台入口 | identity 私有入口 | 请求体与成功结果 |
|---|---|---|---|
| 发布 | `POST /api/identity/keys/publish` | `POST /internal/identity/auth/keys/publish` | `{"kid":"new_kid"}` → `{"kid":"new_kid","status":"PUBLISHED"}` |
| 激活 | `POST /api/identity/keys/activate` | `POST /internal/identity/auth/keys/activate` | `{"kid":"new_kid"}` → `{"kid":"new_kid","status":"ACTIVE"}` |
| 正常退役 | `DELETE /api/identity/keys/{kid}` | `DELETE /internal/identity/auth/keys/{kid}` | 无请求体 → `{"kid":"old_kid","status":"RETIRED"}` |
| 紧急吊销 | `POST /api/identity/keys/{kid}/revoke` | `POST /internal/identity/auth/keys/{kid}/revoke` | 无请求体 → `{"kid":"old_kid","status":"REVOKED"}` |
| 查询原结果 | `GET /api/identity/key-operations/{operationId}` | `GET /internal/identity/auth/key-operations/{operationId}` | 无请求体、无查询参数；结果合同见第 3 节 |

发布、激活只接受精确的 `kid` 字段。私有退役、吊销也接受 JSON `null`；不能附加新字段。`kid` 是 1–80 位 ASCII 字母、数字、下划线或连字符，发布后不可更换其 `kid/n/e`。同一 `kid` 再发布，即使材料相同，使用新 operation 也返回 409；已退役或吊销的 `kid` 不能重新激活。

平台操作者必须是平台租户根组织的当前 `EMPLOYEE`，拥有实际授予且当前有效的 `system:oauth:keys` 菜单权限，以及完整有效的 canonical BFF、SSO、原 grant、客户端策略和成员来源。`system:oauth` 导航权限不能代替该细权限。每次敏感写入要求原 canonical 来源上最近 **5 分钟内**的真实 TOTP 验证，未来时间或恢复码不能满足此要求。需要刷新验证时，走平台 `/auth/step-up?return=/system/oauth/clients` 重新主认证和 TOTP，并在新的有效平台会话中开始后续操作；仅打开安全页面不会更新旧 grant 的 MFA 事实。

平台写入还必须携带该 BFF 的 Cookie、准确控制台 `Origin`、当前 `X-CSRF-Token` 和预先保存的 `X-Identity-Operation`。禁止把浏览器 Cookie、CSRF 或任何 secret 写入操作记录。平台按当前授权建立 `platform_auth_command_intents`，identity 使用窄函数复核；持有服务 secret 本身不能产生人的授权事实。

平台到 identity 使用独立 `KEY_ADMIN` 服务登记，对应 `IDENTITY_KEY_ADMIN_SERVICE_CLIENT_ID` 与 `IDENTITY_KEY_ADMIN_SERVICE_CLIENT_SECRET`。服务 ID 为规范 UUIDv7，secret 为 64 位小写十六进制；私有 Basic 认证不接受 Cookie。该凭据不能与 `AUTH_ADMIN`、`ACCOUNT_COMMAND`、其他内部用途或 RP/MACHINE 凭据复用。公开网关应拒绝 `/internal/identity/*`；只有配置的私有 HTTPS 服务通道可访问这些入口。

## 2. 外部私钥准备与实例发布

identity 不生成私钥，也不从数据库读取私钥。每个实例通过绝对 `OIDC_KEYSET_PATH` 在**启动时**加载外部 JSON；修改文件不会热加载。密钥集格式如下，尖括号内容均为格式占位符，不能作为实际材料：

```json
{
  "keys": [
    {
      "kid": "rotation_A",
      "privateKeyPem": "<RSA private PEM, with JSON-escaped newlines>",
      "n": "<canonical unpadded base64url RSA modulus>",
      "e": "AQAB"
    },
    {
      "kid": "rotation_B",
      "privateKeyPem": "<independently generated RSA private PEM>",
      "n": "<matching canonical unpadded base64url RSA modulus>",
      "e": "AQAB"
    }
  ]
}
```

文件最多 512 KiB，包含 1–8 把不同 `kid` 的密钥，字段严格校验。算法固定为 RS256，RSA 模数为 2048–4096 位、无前导零、使用规范无填充 base64url，指数只能是 65537（`AQAB`），单个私钥 PEM 最多 16384 字节。加载会实际签名并验签，拒绝私钥与 `n/e` 不匹配、非 RSA 材料及非法 JSON。配置失败应阻止该实例启动，不能忽略失败继续接流。

1. 在受控密钥管理环境独立生成 B，赋予从未使用的新 `kid`，提取其真实匹配的 `n/e`。保留仍承担签名的 A；不要通过复制 A 私钥伪造新的独立密钥。
2. 将包含 A/B 的新材料安全分发到**每个候选 identity 实例**。文件及父目录只允许服务身份和必要运维身份读取；Unix 使用私有目录与 0600 文件，Windows 核对实际 ACL。不要提交到源码、命令行、工单、报告、构建产物或普通日志。
3. 按部署流程逐个排空、重启实例，记录实例标识、实际加载版本、启动时间以及 A/B 的公开指纹，核对全部候选实例已经重新启动。可用规范 JWK `{"e":"AQAB","kty":"RSA","n":"..."}` 的 RFC 7638 SHA-256 指纹比较公开材料；不要输出 PEM。
4. 在 A 仍活动时验证各实例的当前业务签发、健康与有界失败行为。存活探针或通用 readiness 不能单独证明未来活动 B 的私钥已经部署到所有实例；须保留该实例的受控配置加载及重启记录。
5. 每个实例均具备 A/B 后，才进入发布与激活。缺 B 的旧实例一旦读到活动 B 会拒绝签发；它不会自动回退 A，也不会自动从文件重新读取 B。

一个数据库活动集合供所有实例共用，不应逐实例创建不同的活动 key。数据库的唯一活动索引阻止同时出现两个活动 `kid`；它不能代替外部材料分发。

## 3. 原操作编号、期限与未知结果

每一次新的发布、激活、退役或吊销，在发送前生成并保存一个**规范 UUIDv7**，同时保存非秘密的动作、完整目标路径和原 `kid`。相同编号不能用于另一动作或另一密钥。平台 admission 使用该 UUID 时间：数据库时钟须处在编号时间前 30 秒至后 60 秒内，故不要提前批量生成编号，也不要修改系统时间以绕过期限。

平台计算并持久化 SHA-256 请求摘要，再发送私有 `X-Identity-Operation` 与 `X-Identity-Operation-Digest`。摘要封装为紧凑 UTF-8 JSON，递归按键排序，包含大写 method、完整私有 path、原始解析 body；无请求体使用 JSON `null`。例如发布 B 的摘要输入为：

```json
{"body":{"kid":"rotation_B"},"method":"POST","path":"/internal/identity/auth/keys/publish"}
```

业务操作者通过平台提交，不应自行伪造 intent 或在数据库直接插入授权事实。私有接口仅在已存在且精确匹配 operation、service、摘要、method/path、当前操作者来源的 intent 下执行新操作。intent 自 `accepted_at` 起只有 **60 秒**，锁等待也计入期限。identity 在变更、审计、receipt 插入发生等待后重新检查期限；过期、权限或来源失效应使整个事务回滚。

HTTP 超时、断连或 503 不能说明变更未提交。平台若返回 `OIDC_REMOTE_RESULT_UNKNOWN`，保留响应的原 `operationId`，通过原平台会话查询 `GET /api/identity/key-operations/{operationId}`：

| 查询结果 | 操作规则 |
|---|---|
| `state=COMPLETED`，携带 `result` | 采用原结果，继续下一步；不要再次生成编号重复该动作 |
| `state=NOT_APPLIED` | 平台已在原锁与期限条件下确认未执行；先检查当前密钥状态和来源，再为确需执行的新动作生成新编号 |
| 503 或结果仍不确定 | 继续查询原编号，保持动作暂停，不推断成功或失败 |
| 403/409，原会话、服务登记或凭据已变化 | 保留原编号及非秘密证据，核对归属与当前授权；不能换 secret、会话或编号碰撞恢复 |

平台查询仍要求原 actor/session 归属、当前细权限和近期 TOTP。避免在一个结果未确认时退出、切换组织或重建平台会话；若 TOTP 期限已过，只能按当前来源与管理恢复合同处理，不能绕过为任意会话重绑 intent。

私有恢复调用使用原 `KEY_ADMIN` 服务 ID、**未轮换的原服务 secret**、原摘要及原 operation 路径，无查询字符串；可选 operation header 必须与路径一致。私有 200 返回原成功 DTO；已提交结果可在 intent 到期后恢复。私有 404 只表示在相同 operation 锁下暂未找到 receipt，不能独自认定 `NOT_APPLIED`。服务、摘要、method/path 或 secret hash 不同会冲突。服务 secret 轮换会阻止恢复原 receipt；计划轮换服务凭据前先结清所有未知结果。

密钥状态变更、对应 `OIDC_PUBLISH_KEY` / `OIDC_ACTIVATE_KEY` / `OIDC_RETIRE_KEY` / `OIDC_REVOKE_KEY` 审计及 `identity_auth_command_receipts` 在同一事务提交。只保存公开 `kid`、原 operation、动作、状态、时间及脱敏审计定位，不记录请求认证头、私钥或 token 正文。

## 4. 正常轮换：A → B

1. 完成第 2 节的全部实例准备。读取真实 issuer 的发现文档与 `/oauth/jwks`，记录 A 的公开指纹，并以获准的只读身份核对 A 为唯一活动 key。B 在未发布前激活应被拒绝，不能跳过发布步骤。
2. 用新 operation 发布 B，等待明确的 `PUBLISHED` 结果或按第 3 节恢复原结果。此时 JWKS 应含 A/B，A 继续签发。发布不会自动切换活动 key。激活前须满足目标 RP 的实际 JWKS 缓存刷新窗口，并保留新 key 的真实预发布时间、客户端缓存年龄和接收结果；刚发布就激活可能被仍缓存旧集合的标准客户端拒绝。
3. 用另一个新 operation 激活 B，等待明确的 `ACTIVE` 结果。激活持有生命周期事务锁，原子清除旧活动状态并选择 B。切换过程中并发请求可能等待或按有界策略失败；不要将这种失败改成旧密钥回退。
4. 分别经实际实例完成获准的新 ID Token 签发及投递签名观察。新 ID Token 头部应为 `alg=RS256`、`kid=B`、`typ=JWT`；backchannel 使用 `typ=logout+jwt`，其他签名投递使用 `identity-delivery+jwt`，都共用当前活动 key。使用受控工具只记录头部和验证结论，不持久化 token。
5. 用当前 JWKS 验证仍未过期的 A token 与合法 B token；核对平台及客户门户的实际新登录/回调，需同时满足 issuer、audience、类型、nonce、期限和来源检查。第三方 RP 单独记录其 JWKS 缓存策略与实际结果。
6. 保留 A 的公开生命周期行。通过下列只读查询取得**数据库当前最后签发高水位**及允许退役时间，等到数据库时钟严格超过该时间后再发起正常退役。不要只按激活 B 的时间、某枚抽样 ID Token 或配置 TTL 推算。

```sql
SELECT clock_timestamp() AS observed_at,
       kid, active, published_at, activated_at, retired_at, revoked_at,
       last_signed_exp,
       last_signed_exp + interval '60 seconds' AS retain_until,
       NOT active AND retired_at IS NULL AND revoked_at IS NULL
         AND (last_signed_exp IS NULL
              OR last_signed_exp + interval '60 seconds' < clock_timestamp())
         AS can_retire_now
FROM public.auth_signing_keys
ORDER BY kid;
```

7. 用新 operation 正常退役 A。活动 A 或仍处在 `last_signed_exp + 60 秒` 窗口内会返回 409；以原结果与新读回确认后再安排下一次确需执行的请求，不用新编号无界重试。
8. 退役提交后，A 应从新 JWKS 消失，B 继续签发与验证；A 的旧 token 此时应已过期。保存真实等待的起止时间与高水位。当前 canonical 人员授权码签发的 Access Token 和 ID Token 共同采用最多 300 秒、并受原 grant／在线来源期限约束的真实 deadline，refresh Access Token 同样最多 300 秒。当前版本没有旧的 token TTL 覆盖配置；不能把演练请求标签的 30 或 600 当作 canonical 生效期限，须核对实际返回及数据库 deadline。logout 等签名投递也会延长高水位。
9. 按外部保管策略处理 A 私钥，下一次受控实例发布可从运行 keyset 移除终态 A，以保持 1–8 把限制。保留数据库公钥行、终态、签发高水位、审计与 receipt；不得删除后重新使用相同 `kid`。

签名事务会对当前 key 行加 `FOR UPDATE` 并保持到调用方事务提交；`last_signed_exp` 以 `GREATEST` 更新，多个实例和不同 token 类型不能用较短期限覆盖较长期限。激活、退役、吊销与这些事务争用同一 key 行，正常退役不能漏过已经提交的最后一枚签名。回滚事务没有可供业务返回的已提交 token，也不提交其高水位。不要用 SQL 将高水位调小、删除行或停用触发器来缩短等待。

当前独立示例锁定 `openid-client 6.8.8`／`oauth4webapi 3.8.8`：新 `kid` 不在已缓存 JWKS 中时，缓存年龄达到 60 秒才允许该标准库重新读取，否则拒绝签名。Phase 23 演练在同一 SDK 进程中只读 `getJwksCache()` 的公开更新时间、年龄和 kid 集合，每把后继 key 预发布后真实等待至少 61 秒，每段等待不超过 10 秒；这不是所有第三方 RP 的通用缓存上限。等待后重新签发仍活动的 A，才用该未过期载体验证 A/B 并存。不得清空／回写缓存、修改时钟、关闭 NonRepudiation 验签或重启 SDK 来冒充正常轮换。

无活动签名 key 的演练在旧 key 仍活动时先完成后继 C/D 的预发布等待及真实管理员 step-up，再依次撤销旧活动 key、验证签发 503、激活已发布的后继 key。此时 JWKS 仍可包含未活动的 C/D，不能将“没有活动签名 key”误写成“没有公钥”。管理员等待期间达到四分钟即在下次敏感写入前真实重新验证，服务端五分钟 TOTP 门禁保持；不得在无活动 key 的窗口内依赖新 ID Token 完成管理员认证。C/D 恢复载体均以实际返回的 `expiresAt` 与 token deadline 为准，配置请求 600 不会把 canonical 有效期延长；自然过期不能计作恢复撤销通过。

## 5. 紧急吊销

当 A 私钥疑似泄漏时，根据事件范围选择是否允许先完成 B 的发布和激活。若 B 已安全预置，优先切到 B，再以新 operation 吊销 A；若必须立即停用 A，可直接吊销活动 A，但随后在没有其他活动可用 key 的期间签发将返回不可用。紧急操作仍必须满足当前操作者、TOTP、服务用途、CSRF、intent 与原结果恢复约束。

吊销提交会把目标 `active` 设为 false、写入 `revoked_at` 并从新 JWKS 移除。已吊销 `kid` 不能再激活或覆盖材料。使用独立、从未使用的新 B 恢复签发；不能以重新发布泄漏的 A 或清除 `revoked_at` 作为恢复。

确认当前 JWKS 不含 A，并分别验证当前系统的员工、客户和独立 RP 对 A 的拒绝及 B 的成功。平台与客户门户当前验签路径获取当前 `/oauth/jwks` 并拒绝找不到的 `kid`；JWKS/数据库不可用时保留失败关闭及有界超时/503 行为。未知 `kid`、错误签名、错误 issuer/aud/typ、非 RS256 也应拒绝，不能通过关闭校验应急。

第三方若缓存了 A 公钥，仍可能在 token 到期前完成数学验签。删除 JWKS 条目不会让缓存的 RSA 公钥失去数学效力，不能承诺所有外部 RP 立即拒绝。按登记合同通知其采用当前拒绝事实、刷新缓存并完成自己的会话处置，同时单独记录实际可达性与延迟。

**签名 key 吊销不会自动撤销 opaque Access Token、refresh family、grant、同意或本地会话。** 若事件需要结束这些来源，另行执行当前 canonical grant/客户端/账号撤销或注销流程，验证原正常端点确实拒绝；不要把 key-only 吊销当作全部认证状态失效。已泄漏材料、未结清原操作及受影响的投递终态分别保留事件证据。

## 6. 异常处理与回退条件

| 现象 | 核对及处理 |
|---|---|
| 发布返回 400 | 检查 `kid`、精确请求字段及目标进程是否已启动加载对应验证材料；安全重配并重启后再开始确需执行的新动作 |
| 发布/激活返回 409 | 核对已有 `kid/n/e`、是否已发布/终态、intent/摘要/期限及原 operation；不要改写材料或清理 receipt |
| 退役返回 404/409 | 404 可为不存在或已经终态；409 可为活动或验证窗口未结束。先恢复原结果、读取真实状态及高水位 |
| 一个实例激活后无法签发 | 排空该实例，检查其启动材料是否包含与 DB 完全相同的 B，修复并重启后再验证；不能在该实例私自激活另一 key |
| 没有可用活动 key | 保持签发失败关闭，部署安全的新材料，发布并激活独立新 key；JWKS 可为空，不能用空集合证明健康 |
| 审计/receipt 写入失败、锁等待跨期限 | 应无 lifecycle 部分提交；按原 operation 查询并对账数据库状态，解除确定原因后再执行新动作 |
| 数据库/JWKS/TLS 故障 | 保留当前有界拒绝语义，恢复权威库/可信网络/证书；不要转向另一 issuer、旧 token authority 或无限重试 |

若仅为 B 部署故障且 A 仍安全、未退役、未吊销，所有候选实例仍持有 A 的精确材料，可按相同管理合同**显式重新激活 A**。这是一项独立管理动作，须重新记录 operation，并会继续推进 A 的签发高水位。A 已成为终态或疑似泄漏时不得使用该回退。先核对未知激活结果，避免两个操作者相互切换活动集合。

## 7. 备份与隔离恢复边界

数据库备份只保存公钥与生命周期，不能恢复运行所需的外部私钥。将当前及必要保留的签名材料、issuer、公开材料指纹和实例配置版本纳入独立加密保管，与 BFF/context AEAD、TOTP、邀请材料和各用途服务 secret 分开管理。恢复前按真实 `kid/n/e` 核对材料；缺失或不匹配时保持入口关闭，不生成相同 `kid` 的替代私钥。

恢复必须使用当前 [canonical 隔离恢复工具与合同](../../saas-plateform/backend/ops/identity-recovery/README.md)，在新隔离目标完成来源拒绝、版本高水位、秘密轮换和启动栅栏后才允许接流。不要把历史旧表恢复脚本直接指向当前数据库，也不要凭一份旧 dump 重新启用账号、grant 或 key。

签名 key 的备份后拒绝事实和签发高水位必须与独立 witness 对账：吊销/退役按拒绝事实保留，`last_signed_exp` 取所有可信事实的最大值，不能被旧备份缩小；不能为了恢复便利重新激活终态 key。恢复快照时应事先包含可安全使用的候选活动 key，其私钥另有受控备份；缺少完整 witness、材料、owner/ACL、issuer 或当前 source fence 就继续隔离。

恢复认证来源时另行废弃所有恢复前会话与凭据，不以 key 生命周期替代该步骤。对账后实际验证新 JWKS、正确 B 的新签发、旧 key 的拒绝和新员工/客户业务；保留稳定 sub、不可变公钥、审计、receipt、来源墓碑及投递终态。测量真实 RTO/RPO，并把主动失效认证状态与丢失业务数据分别记录。

## 8. 执行记录与资源收尾

正式记录至少包括：目标项目/环境与 issuer、数据库和集群归属、源码/二进制及配置版本、各实例重启、公开 key 指纹、每步原 operation 与动作结果、JWKS 集合、真实 `last_signed_exp` 和等待时间、两 RP/第三方验证结论、未知结果处置、审计定位以及实际资源清理。

演练前限定新建数据库、角色、私有目录、测试进程与监听、备份/witness、故障文件和清理范围，复用适用环境，成功、失败、中断均执行定向清理。不得删除已有业务数据、共享服务或正式脱敏报告。若使用 Docker，依工作区规则记录实际 context、前后 `docker system df`，清除本轮容器、卷、网络、专用镜像和无用构建缓存；不使用全局 prune，也不把 Docker 内部回收等同于 Windows WSL 虚拟磁盘已缩小。

本手册编写只读取当前源码和文档，没有连接数据库、启动应用、创建或复用容器，也没有生成私钥或备份。实际验证结果应由执行报告提供，不能将本手册当作 K01–K09 的 PASS 证据。
