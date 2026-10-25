# SaaS identity authority

`saas-identity` is an independent Rust package and deployment unit for account
authentication, global SSO and the OIDC provider. It has no dependency on platform
or customer-portal business crates. Its public issuer stays
`https://auth.saas.test`; the default internal listener is `0.0.0.0:3041`.

The gateway owns TLS and host routing. Only the authentication host forwards
`/api/sso/*`, `/sso/*`, `/.well-known/openid-configuration` and public `/oidc/*`
to this service. Platform APIs and RP callbacks stay on their existing hosts.
Private `/internal/identity/*` routes must only be exposed to registered service
consumers through authenticated, certificate-verified HTTPS connections.

`src/main.rs` only starts the library. `src/lib.rs` assembles configuration,
read-only readiness, state, routers and graceful shutdown. The process does not
run migrations, create a database, seed users or initialize platform data.
The canonical platform migration job exclusively applies migration 0020 and all
preceding migrations. Provisioning establishes separate runtime/NOLOGIN owner
roles and writes the readiness marker only after grants are verified.

The shared physical `users` table retains stable subject IDs and foreign keys.
Identity only receives explicit authentication-column privileges; it cannot read
or write platform superadministrator policy, members, roles or menus, delete an
account or update its primary key. Runtime retirement is a disabled tombstone.
Platform credentials are denied synchronously through the narrowly owned trigger
bridge and final projections. The platform still makes online authority calls;
neither a valid JWT signature nor an available local projection substitutes for
an unavailable identity authority.

Configuration comes only from explicit process environment. There is no automatic
`.env` lookup. SSO and OIDC default to off. Required enabled-provider settings are:

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | Explicit PostgreSQL business database and identity runtime login |
| `BIND_ADDR` | Internal IP socket; defaults to `0.0.0.0:3041` |
| `APP_ENV` | `development`, `test` or `production`; password policy remains strict in production |
| `SSO_ENABLED` / `OIDC_ENABLED` | Explicit feature activation; both default `false` |
| `SSO_ORIGIN` / `OIDC_ISSUER` | Exact stable `https://auth.saas.test` |
| `OIDC_KEYSET_PATH` | Absolute private RS256 keyset path, mounted read-only |
| `CUSTOMER_PORTAL_OIDC_CLIENT_ID` | Exact registered customer RP accepted by the private access-proof port |
| `SSO_SESSION_TTL_SECONDS` / `SSO_PREAUTH_TTL_SECONDS` | Global session and preauthentication deadlines |
| `OIDC_CODE_TTL_SECONDS` / `OIDC_TOKEN_TTL_SECONDS` / `OIDC_REFRESH_TTL_SECONDS` / `OIDC_INTERACTION_TTL_SECONDS` | Existing bounded provider lifetime settings |

Password worker concurrency, bounded queue, verification deadlines and login rate
settings retain the existing provider names. Per-process capacity is not a
distributed quota; divide the deployment's tested budget among replicas.

Service clients are explicitly provisioned in `identity_service_clients`, with
one separate credential for each of `CUSTOMER_ACCESS_PROOF`, `ACCOUNT_COMMAND`
and `OIDC_ADMIN`. Only hashes are stored. Service credentials, RP secrets and
customer resource credentials must all differ. Private protocol details and
uncertain command-result handling are in [the internal port contract](docs/internal-api.md).

`GET /health`, `/ready`, `/health/ready`, `/healthz` and `/readyz` verify the database, provisioned
role/owner boundary and pinned issuer. Healthy JSON is exactly
`{"status":"UP","service":"saas-identity","issuer":"https://auth.saas.test"}`.
Readiness failure returns 503. SIGTERM and Ctrl-C gracefully drain requests and
close the database pool. Logs do not contain passwords, Authorization headers,
Cookies, tokens, request bodies, private keys or connection strings.

Build and verification commands run from this independent repository:

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked
cargo doc --locked --no-deps
```

Real PostgreSQL, runtime-role, TLS, multi-process client and operational acceptance
results are recorded in the platform identity ledger validation. A source copy or
successful compilation alone does not establish independent-deployment acceptance.
