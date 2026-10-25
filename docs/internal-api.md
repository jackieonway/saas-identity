# Identity internal ports

This service owns account authentication, SSO and the standard OIDC provider.
The public issuer remains `https://auth.saas.test`. Internal hosting addresses do
not change discovery, subjects, Cookie hosts, RP registrations or callbacks.
The platform remains the sole owner of membership and administrator decisions.

## Service authentication

Internal routes require TLS at the private gateway and exactly one HTTP Basic
Authorization header containing a canonical UUIDv7 service ID and its issued
64 lowercase hexadecimal secret. Registration is in the identity-owned
`identity_service_clients` table. It stores only SHA-256 of the secret and one
purpose: `CUSTOMER_ACCESS_PROOF`, `ACCOUNT_COMMAND`, or `OIDC_ADMIN`.
Disabled or wrong-purpose registrations fail closed with 403. These credentials
are distinct from OIDC RP secrets and platform customer-resource credentials;
they cannot obtain human OIDC tokens. Cookie and query authentication are rejected.
Internal JSON rejects unknown fields. Responses have no-store/no-referrer headers.

## Customer access proof

`POST /internal/identity/customer-access-proof`

Purpose: `CUSTOMER_ACCESS_PROOF`.

Request:

```json
{"contractVersion":"customer-access-proof-request/1","oidcAccessToken":"<64 lowercase hex>","expectedClientId":"<canonical UUIDv7>"}
```

The expected RP must equal server configuration `CUSTOMER_PORTAL_OIDC_CLIENT_ID`.
Only an original, currently live access token is accepted: not an ID token,
refresh token, or token belonging to a different RP. The current registration
must have purpose `CUSTOMER_PORTAL`, exactly `["CUSTOMER"]` allowed member types,
and the grant must include both `openid` and `profile`. Its original issuer,
grant, sid, subject, account generation, RP policy generation and deadline are
checked online. No membership is selected or returned by this service.

Success 200:

```json
{"contractVersion":"customer-access-proof/1","tokenType":"access_token","clientPurpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],"scope":["openid","profile"],"source":{"issuer":"https://auth.saas.test","clientId":"<UUIDv7>","grantId":"<UUIDv7>","globalSessionId":"<UUIDv7>","userId":"<UUIDv7>","accountVersion":"3","clientPolicyVersion":"1","authTime":1700000000,"expiresAt":"<RFC3339>"},"account":{"id":"<UUIDv7>","username":"<name>","realName":"<display name>","avatar":"<avatar>"}}
```

`scope` reports the complete original grant scope. Versions are canonical decimal
strings. The deadline is the minimum access/grant/SSO deadline and is never extended.
Invalid or retired source is 401; malformed JSON is 400; unavailable authority,
database, capacity or deadline is 503. The platform still performs a second online
proof and its final exact-source deny projection after local business work.

## OIDC administration

Purpose: `OIDC_ADMIN`. The platform performs its own fresh employee, platform-root
and `system:oauth` checks before invoking these private routes. Identity never
reads platform memberships, roles, menus, organizations or `is_super_admin`.

- `GET/POST /internal/identity/oidc/clients`
- `PATCH /internal/identity/oidc/clients/{id}`
- `POST /internal/identity/oidc/keys/publish`
- `POST /internal/identity/oidc/keys/activate`
- `DELETE /internal/identity/oidc/keys/{kid}`
- `POST /internal/identity/oidc/keys/{kid}/revoke`

Bodies and success DTOs preserve the existing platform OIDC management contract.
Client policy updates retain their expected access-policy version. A new client secret is returned on the successful creation response and its
authenticated recovery response; no secret hash or private signing material is exposed.
Signing private material stays in the process's externally provisioned keyset.

### Durable administration recovery

Every mutation above requires exactly one `x-identity-operation` header containing
its canonical UUIDv7 operation ID, and exactly one
`x-identity-operation-digest` header containing 64 lowercase hexadecimal digits.
The digest is SHA-256 of compact UTF-8 JSON with recursively sorted object keys:

```json
{"method":"POST","path":"/internal/identity/oidc/clients","body":{"name":"<original input>","purpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],"redirectUris":["https://customer.saas.test/auth/callback"],"postLogoutRedirectUris":[],"refreshEnabled":true}}
```

`method` is uppercase. `path` is the complete fixed internal path, including an
exact client ID or key ID when applicable. `body` is the original parsed JSON
before trimming, sorting registration arrays or applying policy normalization;
bodyless retire/revoke requests use JSON `null` in this digest envelope. Array
order and explicit nulls remain unchanged. No query parameters are accepted.
The platform persists its fresh administrator authorization acceptance and this
exact operation/service/digest/method/path binding before forwarding.

Identity serializes a new operation by transaction-scoped advisory lock. An
existing receipt must match the service ID, request digest, method, full path and
SHA-256 of the service credential. New execution additionally proves the accepted
platform intent through the narrow
`identity_oidc_command_intent_active(operationId,serviceId,digest,method,path)`
definer, which locks that exact accepted intent and permits only its original
60-second window. Identity rechecks the window after provider/audit waits and
receipt insertion. Provider mutation, nonsecret audit and safe receipt commit in
one transaction; no automatic retry repeats a completed lifecycle mutation.

Recovery uses:

```text
GET /internal/identity/oidc/operations/{canonical UUIDv7}
x-identity-operation-digest: <original 64 lowercase hex digest>
Authorization: Basic <the same OIDC_ADMIN service credential>
```

There is no query string. An optional `x-identity-operation` must match the path.
Success 200 returns the original success DTO, even after the original accepted
intent expires. Unknown operation is 404 and remains an unknown transport outcome;
a service/digest/operation-content conflict is 409. Authentication, response limits
and no-store/no-referrer protections remain active on recovery.

For creation, the client ID equals the operation ID. Its 64 lowercase hexadecimal
client secret is derived as HMAC-SHA256 with the authenticated service secret's
UTF-8 bytes as key, and these exact UTF-8 message bytes:

```text
saas-identity/oidc-admin-client-secret/1\n<operationId>\n<requestDigest>
```

The two `\n` sequences above each denote one LF byte; there is no final newline.
The safe durable receipt removes `clientSecret` and contains no raw service secret,
client secret, PHC or private key. A recovery request using the original service
ID and unchanged service credential deterministically reconstructs that creation
secret in the response. After the service secret rotates, the old receipt returns
409 and requires explicit client reprovisioning; it cannot silently reconstruct a
different credential or issue a replacement client under the old operation ID.

## Account commands

Purpose: `ACCOUNT_COMMAND`. The platform owns administrator authorization and a
same-database durable intent acceptance point. Identity receives no platform
Bearer token, roles, permissions or authorization decision objects. No PHC hash,
`PreparedPassword` or local transaction crosses the HTTPS port.

The read and password-proof routes use strict JSON with exactly these fields:

| Method and path under `/internal/identity/accounts` | Request | Success 200 |
| --- | --- | --- |
| `POST /candidates` | `{identifier,phone,email}` strings, with the caller's existing normalized phone/email aliases | `{accounts:[{id,username,realName,status,accountVersion}]}` |
| `GET /{id}` | Canonical UUIDv7 path; no query | `{id,username,realName,status,accountVersion}` |
| `POST /verify` | `{id,expectedAccountVersion,password}` | `{verified:true}` or `{verified:false}` |
| `POST /login` | `{id,expectedAccountVersion}` | `{recorded:true}` |

Every account version is a canonical nonnegative decimal **string**. Candidate
lookup retains username/phone/email matching and the existing limit of 65; a
legacy username-only consumer sends empty phone and email. Password verification
uses the bounded Argon2 worker, then checks the exact original hash, enabled
status and account version online again. A wrong password, absent account or
retired generation yields `verified:false`. Recording login only updates the
exact enabled account generation supplied by the consumer; it never creates a
session or adopts a newer generation. These DTOs contain no password hashes.

`POST /internal/identity/accounts/commands` accepts exactly:

```json
{"operationId":"<canonical UUIDv7>","targetUserId":"<canonical UUIDv7>","expectedAccountVersion":"0","expiresAt":"<RFC3339>","canonicalDigest":"<64 lowercase hex>","kind":"CHANGE_PASSWORD","payload":{"oldPassword":"<request only>","newPassword":"<request only>"},"context":{"userId":"<target UUIDv7>","sessionId":"<original platform session UUIDv7>","tenantId":"<UUIDv7>","organizationId":"<UUIDv7>","accountVersion":"0"}}
```

`context` is required for `CHANGE_PASSWORD` and is `null` for every other kind.
The top-level `context` value participates in the digest, including explicit
`null`. Unknown top-level, context or payload fields are rejected.

| `kind` | Exact `payload` fields |
| --- | --- |
| `CREATE` | `{username,realName,email,phone,gender,password}` strings; expected account version is `"0"`; the platform supplies the new canonical UUIDv7 target |
| `UPDATE_PROFILE` | Optional `realName`, `email`, `phone`, `gender`; absent/null values preserve the old field |
| `SET_STATUS` | `{status:"ENABLED"}` or `{status:"DISABLED"}` |
| `RESET_PASSWORD` | `{newPassword}` |
| `CHANGE_PASSWORD` | `{oldPassword,newPassword}` plus the original context above |
| `REVOKE_ALL` | `{}` |
| `RETIRE` | `{}` |

The digest is **HMAC-SHA256**, keyed by the authenticated service's issued secret
as UTF-8 bytes. To calculate it, remove only top-level `canonicalDigest` from the
original parsed JSON object; recursively sort all object keys; keep array order,
values, explicit nulls and the original `expiresAt` string unchanged; serialize
compact UTF-8 JSON with no whitespace; HMAC those bytes; encode 32 bytes as 64
lowercase hexadecimal characters. Do not normalize a timestamp through a
DateTime serialization, omit nulls, or hash an unsalted plaintext password by
itself. The keyed digest is safe to persist as an operation binding; the password
request, canonical JSON bytes and payload are never persisted or logged.

A new command must expire strictly after the current database clock and no more
than 60 seconds in the future. The platform currently issues a 50-second intent.
Identity takes a transaction-scoped operation advisory lock, returns any existing
same-service/same-digest receipt first, then validates the original deadline,
prepares a password through the bounded worker and locks the target account.
It checks the exact platform intent's operation/target/version/digest/kind through
`platform_account_command_intent_active`, whose narrow definer locks only the
accepted intent. Identity has no direct permission on the platform intent table.

For personal password changes, identity holds the account lock and invokes
`platform_password_context_active(userId,sessionId,tenantId,organizationId,accountVersion)`.
That narrow boolean definer locks the original exact employee member and session
until commit. Identity rechecks it after any audit wait and immediately before
its own generation change retires that source. The password replacement, global
generation increase, nonsecret authentication audit and completed result receipt
are atomic. Expiry is checked again after dependency work and receipt insertion.
The platform's constrained generation trigger bridge synchronously retires its
credentials; identity cannot directly query or mutate those credential tables.

Success 200 and operation lookup use the same exact receipt:

```json
{"operationId":"<UUIDv7>","targetUserId":"<UUIDv7>","canonicalDigest":"<64 lowercase hex>","state":"COMPLETED","beforeVersion":"0","afterVersion":"1","revokedSessions":2,"revokedTokens":3}
```

`revokedSessions` and `revokedTokens` are actual affected-row counts published
by the constrained invalidation bridge in the authentication-owned
`identity_account_revocation_facts` row for the exact target and new generation.
Identity cannot read the underlying platform session/token tables. CREATE,
UPDATE_PROFILE and any command that leaves the generation unchanged return zero;
they never reuse a previous operation's fact for that generation. A revoking
generation change without its exact bridge fact fails closed and rolls back.
Before/after generations in the receipt come from the locked account.
`RETIRE` disables the account, increases its generation and creates an
authentication-owned tombstone. It preserves the subject, login name and user
row, and cannot hard-delete platform membership through an FK cascade. A new
operation cannot mutate or re-enable a tombstoned account.

`GET /internal/identity/accounts/operations/{operationId}?digest=<64 lowercase hex>`
is the only account endpoint accepting a query. It accepts exactly one literal
`digest` parameter, without percent encoding, duplicates or additional parameters.
The authenticated service ID is part of receipt ownership. Existing receipt
lookup precedes account generation, context and expiry checks: it remains usable
after the original successful command revoked its own context or expired. Reuse
of an operation ID with a different digest or service is 409; no other service's
receipt content is returned.

Malformed input or password policy is 400, an unknown receipt/account is 404,
version/digest/expired-intent/original-password/context conflict is 409, and an
unavailable authority/database/budget is 503. Invalid service authentication or
purpose is 403 and consumers treat it as unavailable infrastructure. Unknown
transport outcomes remain unknown until receipt reconciliation; consumers do not
replay old plaintext-password requests or silently adopt a later generation.

## Migration and readiness

The canonical platform migration job exclusively executes migration 0020 and its
predecessors. This service has no migrator, seed or automatic DDL. Normal startup
reads the provisioned `identity_deployment_state` and requires schema version 20,
the exact issuer and its configured runtime identity. A runtime must not be an
owner, superuser, owner-role member, schema creator or database creator. Account
DELETE, primary-key UPDATE and platform policy access are unavailable to it.

Receipt lookup and every OIDC management mutation acquire the same operation advisory transaction lock before reading the original receipt. A missing receipt remains UNKNOWN while its accepted intent is live or the authority is unavailable. Only after the platform's database clock proves the original 60-second intent has expired, and the synchronized lookup returns 404, may the platform report NOT_APPLIED. Recovery never re-dispatches the old mutation or password payload.
