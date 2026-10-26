# 独立身份服务

Rust/Axum 认证中心，负责账号、密码保护、全局 SSO、标准 OIDC、RP 登记和私有身份命令。平台与客户门户分别使用员工 RP 和客户 RP，拥有独立回调、Cookie 和用途。

身份服务与平台共享物理 PostgreSQL 数据库，但使用不同 owner 和受限 runtime。唯一平台迁移作业建立当前 `0001_init.sql`，随后完成[角色交接](../saas-plateform/backend/ops/identity-deployment/README.md)。身份进程不建库、不迁移、不 seed；readiness 核对当前新库版本 1、固定 issuer 和角色归属。

网关只在认证主机转发 `/api/sso/*`、`/sso/*`、发现文档和公开 `/oidc/*`。私有 `/internal/identity/*` 仅允许登记服务通过校验证书的 HTTPS 调用，见[内部协议](docs/internal-api.md)。

配置只读取显式进程环境。按实际部署提供 `DATABASE_URL`、`BIND_ADDR`（默认 3041）、`APP_ENV`、`SSO_ENABLED=true`、`OIDC_ENABLED=true`、准确 HTTPS `SSO_ORIGIN`/`OIDC_ISSUER`、绝对 `OIDC_KEYSET_PATH` 和独立服务凭据。签名私钥、RP secret、内部服务 secret 和客户资源凭据必须不同。

`GET /health`、`/ready` 等探针校验数据库、角色与 issuer，失败返回 503。退出优雅关闭连接；日志不能包含密码、PHC、Cookie、token、私钥或连接串。

在本仓库执行 `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets`。全新安装步骤见[数据库边界](../saas-plateform/backend/docs/fresh-installation.md)，不再使用旧阶段台账或 UUID 搬迁流程。
