# 独立身份服务

Rust/Axum 认证中心，负责账号、密码保护、全局 SSO、标准 OIDC、RP 登记和私有身份命令。平台与客户门户分别使用员工 RP 和客户 RP，拥有独立回调、Cookie 和用途。

统一实施依据见[总体方案](../saas-plateform/backend/docs/designs/unified-oauth-oidc-sso-architecture.md)及[任务台账](../saas-plateform/backend/docs/designs/unified-oauth-oidc-sso-task-ledger.md)。canonical `auth_*` 登记与 `/oauth/*` 已实现人员、机器及业务上下文协议；各 BFF、资源消费者使用该权威；旧登记、旧签发与旧 consent 路由已从当前源码移除。

身份服务与平台共享物理 PostgreSQL 数据库，但使用不同 owner 和受限 runtime。唯一平台迁移作业建立当前 `0001_init.sql`，随后完成[角色交接](../saas-plateform/backend/ops/identity-deployment/README.md)。身份进程不建库、不迁移、不 seed；readiness 核对当前新库版本 1、固定 issuer 和角色归属。

平台应用最小投影使用独立 `APPLICATION_PROJECTION` 服务凭据及 UUIDv7 operation ID/摘要。平台 runtime 不能直读身份投影表；未知提交结果只查询原操作，不能改用新 operation ID 重放。新 `auth_*` 表承载统一客户端、同意及 grant/token 权威；旧 OAuth/OIDC 表不属于当前全新安装基线。

统一客户端管理 API 使用另一组 `AUTH_ADMIN` 私有服务凭据，读写身份域 `auth_*` 客户端、资源/scope 权限、凭据和 consent groups。平台按操作检查当前平台根组织员工的细权限，敏感写入强制校验原 canonical BFF/SSO 来源上最近 5 分钟的 TOTP；`system:oauth` 仅保留导航用途。组成员变化推进 group version，使先前 consent 在用户再次确认前不能用于新成员。列表与详情不返回 secret；机密客户端的创建/轮换 secret 只在原 operation 响应/查询中恢复，数据库 receipt 只保存无 secret 结果。凭据最多有效 90 天，轮换的旧 secret 最多重叠 24 小时；紧急撤销提升客户端策略代际。签名密钥使用独立 `KEY_ADMIN` 服务和 `/internal/identity/auth/keys/*`；原操作通过 `/internal/identity/auth/key-operations/{id}` 查询。

网关只在认证主机转发 `/api/sso/*`、`/sso/*`、发现文档和公开 `/oauth/*`。旧 `/oidc/*` 入口已移除；发现文档只发布 canonical `/oauth/*` 能力。私有 `/internal/identity/*` 仅允许登记服务通过校验证书的 HTTPS 调用，见[内部协议](docs/internal-api.md)。

客户 BFF 使用 `/internal/identity/auth/customer-account-proof`，以独立的 `CONTEXT_SELECTION_SOURCE` 服务身份和精确 `allowed_auth_clients` 取得 canonical 客户账号证明；opaque `sub` 与 UserInfo 一致，内部账号 ID 只从私有 `userId` 字段取得。平台读取客户本人资源时使用反向 `/internal/identity/customer-access-proof` 和另一组 `CUSTOMER_ACCESS_PROOF` 凭据。两方向均只接受当前 CUSTOMER_PORTAL / USER / PLATFORM_CONTEXT 来源，不复用员工证明、共享 secret 或旧 `oidc_*` token；客户成员选择、门户独立会话及恢复仍由各自阶段验收。

资源服务通过私有 `/internal/identity/auth/resource-access-proof` 和独立 `RESOURCE_ACCESS_PROOF` 身份校验 canonical Access Token，服务的 `allowed_auth_resources` 必须明确列出目标资源。资源、audience、单个所需 scope 和 token 当前 scope 必须同时匹配；USER 仅接受在线 PLATFORM_CONTEXT 并返回原选定成员 ID/类型，MACHINE 只返回机器 grant/凭据版本，不伪造人员信息。资源服务继续拥有业务成员、动作和数据范围判断；该证明不替代业务授权。详见[内部资源证明合同](docs/internal-api.md#canonical-private-resource-access-proof)。

canonical `/oauth/token` 支持 USER 的 `authorization_code`、`refresh_token` 和独立 MACHINE 的 `client_credentials`。Access/ID Token 默认为 5 分钟；ACCOUNT_ONLY 与 PLATFORM_CONTEXT 在线 refresh 受原 SSO session 绝对期限及 30 分钟 idle 限制。仅在客户端启用 `refresh_token`、应用 scope 清单与客户端权限均包含 `offline_access`，且用户已明确同意该 scope 时，ACCOUNT_ONLY family 才使用 7 天绝对期限和 24 小时 idle。PLATFORM_CONTEXT 不允许离线授权。客户端可通过 `/oauth/revoke` 撤销自己签发的 access token 或 refresh family；机器凭据绑定其登记版本与精确资源/scope，不带人员身份。

人员 code exchange 的 ID Token 包含原 grant 的不透明 `sid`，跨该 grant 的 refresh 保持稳定；它不暴露全局 SSO session ID。机密 USER RP 使用 Basic 认证调用 `POST /oauth/logout`，传入原 token、`sid`、`sub`、UUIDv7 `operation_id` 和 `CURRENT_APP` 或 `GLOBAL`。前者只关闭原 grant，后者关闭原账号全部人员来源，均保留 consent。已提交的原操作可使用相同内容通过 `POST /oauth/logout/operations/{operationId}` 恢复；只有明确 404 `NOT_FOUND` 才可再次发送同一个 operation。发现文档将其标记为 `rp_logout_command_endpoint`，具体字段见[Phase 20 合同](../saas-plateform/backend/docs/designs/unified-auth/phase-20-logout-delivery-contract.md)。

开启中央投递须显式配置 `AUTH_DELIVERY_WORKER_ENABLED=true`，可通过绝对 `AUTH_DELIVERY_CA_FILE` 增加受信 CA。所有目标由 owner 登记，身份 runtime 不能修改；RP 使用 `BACK_CHANNEL` 时，URI、client 和当前 target 代际必须一致，先创建短会话 RP，再核验目标并编辑绑定。发送使用固定 DNS/IP 核验、原主机 TLS 验证，无代理、重定向或隐式重试，单次总期限 3 秒。每轮最多并行 4 个 30 秒租约任务，指数退避 60 秒至 1 小时，最多 8 次且不超过 24 小时；终止原因仅记录固定错误码并生成 `identity_delivery_terminal` 结构化告警。撤销事务只写 outbox，不等待外部服务。任务持久化来源和状态，不保存通知 JWT、邀请 token 或响应正文。只在 `APP_ENV=test` 允许精确 `.test` HTTPS origin 的 `AUTH_DELIVERY_TEST_ORIGINS` loopback 例外，生产配置该字段即拒绝启动。

运行日志未设置 `RUST_LOG` 或为空时默认采用 `info`。显式过滤必须允许 delivery 调度器、worker 和 password 的 WARN，否则以 `IDENTITY_REQUIRED_WARN_LOGGING_DISABLED` 拒绝启动。应采集 `identity_delivery_terminal`、`identity_delivery_tick_unavailable` 和密码压力事件；数据库 TERMINAL/DEGRADED 保留为历史事实。日志采集继续禁止凭证、邀请材料、请求/响应正文及私有配置。

统一客户端元数据固定返回 `logoutMode`、`backchannelLogoutUri`、`backchannelTargetId`；省略输入时默认为短会话及两个空值。仅已有的机密 USER 客户端可绑定 back-channel，且第三方 URI 必须与当前独立审核事实一致。runtime 先读取目标元数据，再通过窄 SECDEF fence 复验精确 client、地址、代际、状态及期限；它没有 owner 目标 CRUD 能力，任意 UUID 也不能自证核验。纯停用或退役保留原配置并允许已过期目标，重新启用及其他编辑必须重新满足当前核验事实。接口约束见[Phase 20 合同](../saas-plateform/backend/docs/designs/unified-auth/phase-20-logout-delivery-contract.md)。

不支持通知的 RP 必须使用不超过 5 分钟本地会话，并在敏感资源请求或至多 60 秒间隔做在线来源检查。`SHORT_SESSION_ONLINE_CHECK` 的通知状态明确为 `DEGRADED`，资源侧原 token 撤销立即生效；接收方故障或永久失败不会恢复已撤销权限。员工与客户 BFF 的固定入口均为 `POST /auth/backchannel-logout`，只接收原 issuer/JWKS 的 RS256 `logout+jwt`、精确 RP audience、原 `sid`/`sub`、事件和 120 秒期限，并持久化 UUIDv7 `jti` 重放屏障。

配置只读取显式进程环境。按实际部署提供 `DATABASE_URL`、`BIND_ADDR`（默认 3041）、`APP_ENV`、`SSO_ENABLED=true`、`OIDC_ENABLED=true`、准确 HTTPS `SSO_ORIGIN`/`OIDC_ISSUER`、绝对 `OIDC_KEYSET_PATH` 和独立服务凭据。启用生产 SSO 还必须提供独立的 `SSO_TOTP_ENCRYPTION_KEY`（64 个十六进制字符、32 个随机字节）；不得复用签名密钥、RP secret、内部服务 secret 或客户资源凭据。

合作方审核另用 `AUTH_REVIEW` 私有服务；平台审核事实和当前版本由窄 intent fence 复验，身份权威仅接受与该事实完全匹配的最小 manifest。生产责任/运营政策未由部署责任人绑定时保持关闭。

受控账号邀请使用 `AUTH_INVITATION`，管理 API 只返回元数据；24 小时邀请的收件人及用途不可更改。签发要求独立 `AUTH_INVITATION_KEYSET_PATH`，以及 owner 登记的唯一有效 `ACCOUNT_ONBOARDING` 接收渠道，并在同一事务写入投递任务。签发后，可信 owner 另外登记精确绑定邀请、接收人、用途、渠道和代际的核验事实。worker 只有在当前任务租约及核验事实均有效时，才在内存中恢复 token 并发送到预先核验的 HTTPS 目标；旧 `delivery-material` 与 claim-only `consume` HTTP 路由已经关闭。

投递正文的 `acceptUrl` 指向 `GET /sso/invitations/{id}`，该 no-store 页面仅返回通用领取表单，不读取或公开邀请元数据。领取者手动输入投递 token、真实 `verificationRef`、新用户名和密码；页面生成 UUIDv7 operation ID，也允许粘贴此前保存的原编号，再以同源 `POST /api/sso/invitations/{id}/accept` 提交。凭证和密码不进入 URL、浏览器存储或日志，提交及离开页面时清空；未知结果保留原编号，需手动重输相同内容重试。成功只显示 `ACCOUNT_CREATED` 和登录入口。邀请消费、新账号、不可变原操作结果及审计在同一事务提交；用户名已存在时拒绝，不按邮件合并或启用旧停用账号。新账号没有业务成员、角色、SSO 会话或 OAuth grant。重复同一原操作只恢复已提交结果；重试数据不能替换原密码或核验来源。投递与领取的字段、owner 事实和密钥隔离见[当前内部协议](docs/internal-api.md#manual-partner-admission-and-controlled-invitations)；Phase 19 的历史 claim-only 验证不代表这一新流程已经验收。

`GET /healthz`、`/livez` 只证明进程存活，不访问数据库；`/health`、`/ready` 等就绪探针校验数据库、角色与 issuer，失败返回 503。数据库池、语句/锁等待、公开认证准入、请求体读取、TCP 接入与空闲连接都有显式上限；来源仅采信真实 peer 和明确配置的 `TRUSTED_PROXY_IPS`。独立 `IDENTITY_METRICS_TOKEN` 启用私有 `GET /internal/identity/metrics`，该路径不得暴露到公开网关。完整默认值、配置范围、指标及告警边界见[Phase 22 运行合同](../saas-plateform/backend/docs/designs/unified-auth/phase-22-monitoring-contract.md)。退出优雅关闭连接；日志不能包含密码、PHC、Cookie、token、私钥或连接串。

在本仓库执行 `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets`。全新安装步骤见[数据库边界](../saas-plateform/backend/docs/fresh-installation.md)，不再使用旧阶段台账或 UUID 搬迁流程。

canonical 分步上下文页面与一次性 code 扩展见[实施合同](../saas-plateform/backend/docs/designs/context-selection-contract.md)及[Phase 12 报告](../saas-plateform/backend/docs/designs/unified-auth/validation/phase-12.md)。`/oauth/*` 使用 `auth_*` consent 与原来源绑定；旧 `/oidc/*` 及 `/api/sso/applications` 路由已移除，当前授权管理只使用 `/api/sso/consents`。组织切换、SSO 退出和令牌到期不会删除已保存的用户 consent。

`/sso/applications` 为认证中心独立的账号授权管理页。当前页面通过 `GET /api/sso/consents` 读取本人 canonical `auth_*` consent，显示同意组、组内客户端、环境、上下文和资源/scope。`POST /api/sso/consents/{consentId}/revoke` 与 `DELETE /api/sso/consents/{consentId}` 都要求 UUIDv7 `operationId`、`expectedVersion`、认证 Cookie、同源来源、CSRF 与账号锁内会话复验；同一 operation 可通过 `GET /api/sso/consent-operations/{operationId}` 查询。撤销按组内客户端原子失效 code、grant、access/refresh token，并为 Phase 20 写入本地 outbox 事件；其他应用和账号不受影响。

`/sso/security` 提供 TOTP 绑定、恢复码展示和停用页面。生产 SSO 必须配置专用 TOTP 加密密钥；认证器密钥以 AES-256-GCM 加密存储，同一 TOTP 时间步只能接受一次，恢复码摘要存储并单次消费。无恢复码时，内部 `AUTH_SECURITY` 接口要求两个不同授权人员的近期密码/TOTP 签名证明；未配置独立恢复服务与真实可信核验流程时保持关闭。平台 `/auth/step-up?return=/system/oauth/clients` 强制重新主认证与 TOTP，建立新的 canonical BFF 来源；直接访问安全页不会把新 MFA 写到旧平台 grant。绑定、停用和恢复写入安全通知 outbox 与审计。outbox 投递由 Phase 20 完成。

“删除记录”只隐藏已撤销 consent 的展示行，保留最小 generation/version 事实并清除 consent scope 展示记录；不会恢复任何 grant，也不会物理删除审计或撤销事实。活动记录和其他账号记录不可删除。重新授权推进版本后，旧标签页的删除请求返回冲突。退出账号或切换组织保留 consent。

授权记录属于身份服务，由平台唯一 `0001` 基线建立，再按角色交接脚本分配给身份 owner/runtime；平台 runtime 无权读写。已有数据库不得通过重写 checksum 接管此结构，须对明确授权的目标执行全新初始化。

认证中心向平台调用时，显式配置 `CONTEXT_PLATFORM_ORIGIN`、`CONTEXT_PLATFORM_SERVICE_ID`、`CONTEXT_PLATFORM_SERVICE_SECRET`、绝对路径 `CONTEXT_PLATFORM_CA_FILE`，并同时提供绝对路径 `CONTEXT_SELECTION_KEY_FILE`。平台服务身份必须独立登记为 `CONTEXT_SELECTION_AUTHORITY` 并限定 RP；加密密钥文件使用 `{ "activeKid": "名称", "keys": [{ "kid": "名称", "key": "32字节随机密钥的无填充base64url" }] }`，与 OIDC 签名密钥、RP 和私有服务密码分开。未配置完整能力时失败关闭。员工与客户选择分别由登记的当前 canonical 客户端和消费者约束。

`CONTEXT_PLATFORM_ORIGIN` 必须使用证书 SAN 匹配、网络范围受限的私有 HTTPS 入口。平台公开网关固定拒绝 `/internal/*`；不要将公开控制台地址直接填作该私有服务入口。
