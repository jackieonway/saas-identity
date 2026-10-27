# 独立身份服务

Rust/Axum 认证中心，负责账号、密码保护、全局 SSO、标准 OIDC、RP 登记和私有身份命令。平台与客户门户分别使用员工 RP 和客户 RP，拥有独立回调、Cookie 和用途。

身份服务与平台共享物理 PostgreSQL 数据库，但使用不同 owner 和受限 runtime。唯一平台迁移作业建立当前 `0001_init.sql`，随后完成[角色交接](../saas-plateform/backend/ops/identity-deployment/README.md)。身份进程不建库、不迁移、不 seed；readiness 核对当前新库版本 1、固定 issuer 和角色归属。

网关只在认证主机转发 `/api/sso/*`、`/sso/*`、发现文档和公开 `/oidc/*`。私有 `/internal/identity/*` 仅允许登记服务通过校验证书的 HTTPS 调用，见[内部协议](docs/internal-api.md)。

配置只读取显式进程环境。按实际部署提供 `DATABASE_URL`、`BIND_ADDR`（默认 3041）、`APP_ENV`、`SSO_ENABLED=true`、`OIDC_ENABLED=true`、准确 HTTPS `SSO_ORIGIN`/`OIDC_ISSUER`、绝对 `OIDC_KEYSET_PATH` 和独立服务凭据。签名私钥、RP secret、内部服务 secret 和客户资源凭据必须不同。

`GET /health`、`/ready` 等探针校验数据库、角色与 issuer，失败返回 503。退出优雅关闭连接；日志不能包含密码、PHC、Cookie、token、私钥或连接串。

在本仓库执行 `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets`。全新安装步骤见[数据库边界](../saas-plateform/backend/docs/fresh-installation.md)，不再使用旧阶段台账或 UUID 搬迁流程。

统一身份选择的分步页面与 code 扩展见[实施合同](../saas-plateform/backend/docs/designs/context-selection-contract.md)及[验证记录](../saas-plateform/backend/docs/designs/centralized-context-selection-verification.md)。页面只展示必要步骤：账号登录后首次确认应用授权；后续通过 `oidc_consents` 持久记录复用同一账号的授权，退出登录、令牌到期及组织切换不会清除授权。请求新增 scope 时重新确认新增访问范围；重复的 `prompt=consent` 不清除已有授权。只有一个租户时直接展示组织，选定租户下只有一个可用成员身份时自动通过受 CSRF 保护的确认接口继续；搜索结果只有一条不触发自动选择。最终来源和成员检查通过前不签发授权码，浏览器不接收一次性选择凭据。

`/sso/applications` 为认证中心独立的应用授权管理页，可直接登录统一账号，查看已授权/已撤销的应用及其 scope、授权/撤销时间。`GET /api/sso/applications` 仅返回当前 SSO 账号记录；`POST /api/sso/applications/{client}/revoke` 必须同时通过 Cookie、来源、会话 CSRF 和账号锁内重新校验。撤销与授权签发使用同一个账号锁，撤销持久授权、该应用现有 grant 与未完成的授权请求，不影响其他应用授权。标准令牌 revoke 与退出登录不等于撤销持久应用授权。

已撤销列表提供“删除记录”，对应 `DELETE /api/sso/applications/{client}`。入口沿用 Cookie/来源/CSRF/账号锁，在事务中仅删除当前账号已撤销的记录；活动授权返回 409，其他账号或已删除记录返回 404。删除不恢复任何 grant、不清除安全审计，下次进入应用仍须重新同意。若其他标签页已经重新授权，旧页面的删除请求也会被拒绝。

授权记录属于身份服务，由平台唯一 `0001` 基线建立，再按角色交接脚本分配给身份 owner/runtime；平台 runtime 无权读写。已有数据库不得通过重写 checksum 接管此结构，须对明确授权的目标执行全新初始化。

认证中心向平台调用时，显式配置 `CONTEXT_PLATFORM_ORIGIN`、`CONTEXT_PLATFORM_SERVICE_ID`、`CONTEXT_PLATFORM_SERVICE_SECRET`、绝对路径 `CONTEXT_PLATFORM_CA_FILE`，并同时提供绝对路径 `CONTEXT_SELECTION_KEY_FILE`。平台服务身份必须独立登记为 `CONTEXT_SELECTION_AUTHORITY` 并限定 RP；加密密钥文件使用 `{ "activeKid": "名称", "keys": [{ "kid": "名称", "key": "32字节随机密钥的无填充base64url" }] }`，与 OIDC 签名密钥、RP 和私有服务密码分开。未配置完整能力时失败关闭。当前仍不可据此启用客户门户的完整统一选择流程。

`CONTEXT_PLATFORM_ORIGIN` 必须使用证书 SAN 匹配、网络范围受限的私有 HTTPS 入口。平台公开网关固定拒绝 `/internal/*`；不要将公开控制台地址直接填作该私有服务入口。
