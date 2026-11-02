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
purpose: `CUSTOMER_ACCESS_PROOF`, `CONTEXT_SELECTION_SOURCE`, `RESOURCE_ACCESS_PROOF`, `ACCOUNT_COMMAND`, `KEY_ADMIN`, `APPLICATION_PROJECTION`, `AUTH_ADMIN`, or the separately registered `AUTH_SECURITY`.
Disabled or wrong-purpose registrations fail closed with 403. These credentials
are distinct from OIDC RP secrets and platform customer-resource credentials;
they cannot obtain human OIDC tokens. Cookie and query authentication are rejected.
Internal JSON rejects unknown fields. Responses have no-store/no-referrer headers.

## Customer access proof

`POST /internal/identity/customer-access-proof`

Purpose: `CUSTOMER_ACCESS_PROOF`, with the exact customer client in
`allowed_auth_clients`. This credential belongs to the platform-to-identity
resource-proof direction and is separate from the customer BFF's source service.

Request:

```json
{"contractVersion":"customer-access-proof-request/1","oidcAccessToken":"<64 lowercase hex>","expectedClientId":"<canonical UUIDv7>"}
```

The expected RP must equal server configuration `CUSTOMER_PORTAL_OIDC_CLIENT_ID`.
Only an original, currently live access token is accepted: not an ID token,
refresh token, or token belonging to a different RP. The current registration
must be a canonical `auth_*` `CONFIDENTIAL / WEB_BFF / USER / PLATFORM_CONTEXT`
client whose application purpose is `CUSTOMER_PORTAL`, with exactly `["CUSTOMER"]`
allowed member types, and the current token must include both `openid` and
`profile` on the `userinfo` resource. Its original issuer,
grant, sid, subject, account generation, RP policy generation and deadline are
checked online. No membership is selected or returned by this service.

Success 200:

```json
{"contractVersion":"customer-access-proof/1","tokenType":"access_token","clientPurpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],"scope":["openid","profile"],"source":{"issuer":"https://auth.saas.test","clientId":"<UUIDv7>","grantId":"<UUIDv7>","globalSessionId":"<UUIDv7>","userId":"<UUIDv7>","accountVersion":"3","clientPolicyVersion":"1","authTime":1700000000,"expiresAt":"<RFC3339>"},"account":{"id":"<UUIDv7>","username":"<name>","realName":"<display name>","avatar":"<avatar>"}}
```

`scope` reports the current access token scopes, bounded by its original grant,
client permissions, application approval and user consent. Versions are canonical decimal
strings. The deadline is the minimum access/grant/SSO deadline and is never extended.
Invalid or retired source is 401; malformed JSON is 400; unavailable authority,
database, capacity or deadline is 503. The platform still performs a second online
proof and its final exact-source deny projection after local business work.

## OIDC administration

Current signing-key operations use purpose `KEY_ADMIN`. The platform proves a
current employee source in the platform root, the exact `system:oauth:keys`
permission and recent TOTP before accepting a key operation. Identity validates
that original, source-bound intent through the narrow
`identity_auth_command_intent_active` SECURITY DEFINER function; it does not trust
request-supplied administrator claims or have broad access to platform business
tables. The platform remains the business authorization authority.

Key management uses only the following private routes. Current client registration
uses the separate `AUTH_ADMIN` registry described below; key-management credentials
cannot substitute for it. Legacy client registration routes are removed.

- `POST /internal/identity/auth/keys/publish`
- `POST /internal/identity/auth/keys/activate`
- `DELETE /internal/identity/auth/keys/{kid}`
- `POST /internal/identity/auth/keys/{kid}/revoke`

Signing-key bodies contain only `kid` for publish/activate; retirement and emergency
revocation have no body. Success reports the exact key and lifecycle status.
Signing private material stays in the process's externally provisioned keyset.

### Durable administration recovery

Every mutation above requires exactly one `x-identity-operation` header containing
its canonical UUIDv7 operation ID, and exactly one
`x-identity-operation-digest` header containing 64 lowercase hexadecimal digits.
The digest is SHA-256 of compact UTF-8 JSON with recursively sorted object keys:

```json
{"method":"POST","path":"/internal/identity/auth/keys/publish","body":{"kid":"new-key"}}
```

`method` is uppercase. `path` is the complete fixed internal path, including an
exact client ID or key ID when applicable. `body` is the original parsed JSON
before trimming, sorting registration arrays or applying policy normalization;
bodyless retire/revoke requests use JSON `null` in this digest envelope. Array
order and explicit nulls remain unchanged. Mutation and operation-recovery paths
accept no query parameters; only the unified client list accepts its allowlisted
filter/page fields.
The platform persists its fresh administrator authorization acceptance and this
exact operation/service/digest/method/path binding before forwarding.

Identity serializes a new operation by transaction-scoped advisory lock. An
existing receipt must match the service ID, request digest, method, full path and
SHA-256 of the service credential. New execution additionally proves the accepted
platform intent through the narrow
`identity_auth_command_intent_active(operationId,serviceId,digest,method,path)`
definer, which locks that exact accepted intent and permits only its original
60-second window. Identity rechecks the window after provider/audit waits and
receipt insertion. Provider mutation, nonsecret audit and safe receipt commit in
one transaction; no automatic retry repeats a completed lifecycle mutation.

Recovery uses:

```text
GET /internal/identity/auth/key-operations/{canonical UUIDv7}
x-identity-operation-digest: <original 64 lowercase hex digest>
Authorization: Basic <the same KEY_ADMIN service credential>
```

There is no query string. An optional `x-identity-operation` must match the path.
Success 200 returns the original success DTO, even after the original accepted
intent expires. Unknown operation is 404 and remains an unknown transport outcome;
a service/digest/operation-content conflict is 409. Authentication, response limits
and no-store/no-referrer protections remain active on recovery.

The safe durable receipt contains no raw service secret, client secret, PHC or
private key. Key lifecycle operations return only public status. Unified credential
creation uses the distinct `AUTH_ADMIN` flow below, with credential ID equal to the
operation ID and a service/operation/digest-bound `saas-identity/auth-client-secret/1`
HMAC. Credential recovery verifies the original unchanged service secret; rotation
causes a conflict and never reconstructs a different credential.

### Unified client administration (`AUTH_ADMIN`)

The unified registry uses a separate `AUTH_ADMIN` service purpose and credential;
it is not interchangeable with `KEY_ADMIN` or `APPLICATION_PROJECTION`. The
platform checks the current employee source, platform root and the fine
permission for the exact action, including view, registration, rotation or
disable. Sensitive mutations also require recent TOTP and an accepted original
intent. The broad `system:oauth` menu permission alone is insufficient. Identity
uses the narrow accepted-intent fence and its own `auth_*` registry; it does not
replace platform membership or business permission decisions. See the current
[administration and approval contract](../../saas-plateform/backend/docs/designs/unified-auth/phase-19-partner-onboarding.md).

- `GET /internal/identity/auth/clients` with allowlisted `applicationId`, `partnerId`,
  `ownership`, `environment`, `clientType`, `subjectMode`, `status`, `limit` and
  `offset` filters. The default page has 50 entries; `limit` is 1–100, `offset` is
  0–100000. Results sort by creation time and UUID descending and never contain
  secret material.
- `GET /internal/identity/auth/clients/{id}`
- `POST /internal/identity/auth/clients`
- `PATCH /internal/identity/auth/clients/{id}` with `expectedVersion`
- `POST /internal/identity/auth/clients/{id}/credentials` with `expectedVersion`
- `POST /internal/identity/auth/clients/{id}/credentials/revoke` with `expectedVersion`
- `GET /internal/identity/auth/applications/{applicationId}/consent-groups`
- `POST /internal/identity/auth/consent-groups`
- `POST /internal/identity/auth/consent-groups/{groupId}/clients` with `clientId` and `expectedGroupVersion`
- `GET /internal/identity/auth/client-operations/{operationId}` for recovery.

Application status and approved scopes constrain every registration and update.
An application must be `APPROVED` to create or enable clients; each resource and
scope must remain active and each requested scope must belong to the application's
approved projection. Client application, environment, owner, client type, runtime,
subject/context mode, member types, grant types, auth method and consent-group
meaning are immutable after creation. User `WEB_BFF` clients are confidential;
`SPA` and `NATIVE` are public. Machine clients are confidential `SERVICE` clients
using only `client_credentials`, with no redirect or member/context fields.

Client list reads accept only the documented filters and pagination fields. A
page beyond the current end returns an empty `records` array with the same page
metadata and total count. Mutations use the same operation headers and canonical
request digest described above. Updates compare the expected client version under
the client row lock; policy updates advance the policy generation in the same
transaction as permission changes and audit.

Credential creation and rotation are available only for confidential clients.
The returned `clientSecret` is derived from the `AUTH_ADMIN` credential, operation
ID and request digest, then removed from the durable receipt. The exact replay or
`client-operations` lookup of that original operation can reconstruct the same
secret only while the original service credential remains active; retries never
create a second credential. Regular rotation gives the prior credential at most
24 hours of overlap and advances the client version. Emergency revocation removes
all unexpired credential generations and advances both client and policy
versions; public clients never receive a secret. No request, audit record or
receipt stores the raw client secret.

Consent groups are explicit USER-only sets bound to one application, environment,
approved purpose and account/business context. A newly registered client remains
ungrouped unless a manager supplies a group ID or explicitly adds that client.
Every membership addition advances the group version. Existing account consents
record the group version they confirmed, so they cannot authorize a newly joined
client until that user confirms again. Member registration uses the same
operation ID, canonical request digest, audit and receipt-recovery contract as
client administration.

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
{"operationId":"<canonical UUIDv7>","targetUserId":"<canonical UUIDv7>","expectedAccountVersion":"1","expiresAt":"<RFC3339>","canonicalDigest":"<64 lowercase hex>","kind":"CHANGE_PASSWORD","payload":{"oldPassword":"<request only>","newPassword":"<request only>"},"context":{"userId":"<target UUIDv7>","sessionId":"<original platform session UUIDv7>","tenantId":"<UUIDv7>","organizationId":"<UUIDv7>","accountVersion":"1"}}
```

`context` is required for `CHANGE_PASSWORD` and is `null` for every other kind.
The top-level `context` value participates in the digest, including explicit
`null`. Unknown top-level, context or payload fields are rejected.

| `kind` | Exact `payload` fields |
| --- | --- |
| `CREATE` | `{username,realName,email,phone,gender,password}` strings; expected account version is `"0"` for a missing account; the platform supplies the new canonical UUIDv7 target; the persisted account and receipt `afterVersion` start at `"1"` |
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

## Two-person administrator MFA recovery

`POST /internal/identity/security/mfa/recover`

Purpose: `AUTH_SECURITY`.

This private endpoint is not a user-facing reset shortcut. The platform sends
exactly two signed approval statements for different, currently authorized
people. Each statement binds the target, operation ID, approval ID, primary
authentication time, TOTP time and the trimmed support reason digest. Both
timestamps must be no more than five minutes old according to the identity
database clock, and TOTP must follow primary authentication.

```json
{
  "operationId":"<canonical UUIDv7>",
  "targetUserId":"<canonical UUIDv7>",
  "reason":"<protected support verification summary>",
  "approvals":[
    {"userId":"<first approver UUIDv7>","approvalId":"<UUIDv7>","primaryAuthenticatedAt":1793132000,"mfaVerifiedAt":1793132010,"signature":"<64 lowercase hex HMAC-SHA256>"},
    {"userId":"<second approver UUIDv7>","approvalId":"<different UUIDv7>","primaryAuthenticatedAt":1793132005,"mfaVerifiedAt":1793132015,"signature":"<64 lowercase hex HMAC-SHA256>"}
  ]
}
```

Each signature is HMAC-SHA256 keyed by the `AUTH_SECURITY` service secret over
these UTF-8 lines, with no final newline:

```text
saas-identity/mfa-recovery-approval/1
<operationId>
<targetUserId>
<approverUserId>
<approvalId>
<primaryAuthenticatedAt>
<mfaVerifiedAt>
<SHA-256 of the trimmed reason>
```

The platform must verify each approver's role and recent password/TOTP step-up
before signing. Identity checks the signatures, distinct approvers, timestamps
and one-time operation receipt. A successful recovery advances the account
session version, revokes all old SSO sessions, removes the old TOTP factor and
recovery codes, records both approval digests and the audit, and queues a
security notification. Same operation ID and body replay the original result;
reusing the ID with a different body returns 409. The user must sign in and
enroll a new TOTP factor. There is no one-person reset or universal recovery
credential. The platform role and attestation integration is delivered in
Phase 19; until then this endpoint must remain unconfigured.

## Canonical employee BFF account proof

`POST /internal/identity/auth/account-proof` requires a dedicated
`CONTEXT_SELECTION_SOURCE` service credential whose `allowed_auth_clients`
contains the exact employee client. The public gateway rejects this endpoint;
consumers use the private HTTPS origin and its configured CA. They never send
browser cookies to the private interface.

The platform also probes `GET /health/ready` at that private identity origin
before startup. A private reverse proxy must allow that exact health path in
addition to the registered `/internal/identity/*` routes. It returns only service
readiness and the pinned issuer; query-bearing probe variants need not be
allowed. This does not expose private routes through the public gateway.

The request is an exact JSON object with `contractVersion` equal to
`platform-account-proof-request/1`, `expectedClientId` (canonical UUIDv7), and
the server-held opaque `oidcAccessToken`. The access token must belong to that
enabled `CONFIDENTIAL / WEB_BFF / USER / PLATFORM_CONTEXT` client, whose
application purpose is `PLATFORM_CONSOLE` and whose sole member type is
`EMPLOYEE`. Its scopes must contain `openid` and `profile`; this interface
cannot turn an account-only, customer, machine or ID token into an employee
proof.

The response contract `platform-account-proof/1` binds issuer, client ID and
purpose, context mode, member types, scopes, opaque `sub`, internal `userId`,
grant ID, original global session ID, account/client/application generations,
original authentication time, access expiry and absolute grant expiry. Internal
UUIDs are disclosed only through this authenticated proof. A BFF compares `sub`
with the validated ID Token and UserInfo and obtains its internal account ID
from `userId`; it must never parse the pairwise subject as an internal UUID.

Proof production rechecks the original account/session, consent and group
generations, application/client policies, access token and canonical context
binding. A revoked source fails closed. Invalid or expired token sources return
401, malformed requests return 400, unregistered service/client scope returns
403, and unavailable dependencies return 503. No response may be used to repair
an old grant with a newer account, organization or policy generation. The
employee BFF consumes the one-time context result and establishes its session
within the same platform transaction.

## Canonical customer BFF account proof

`POST /internal/identity/auth/customer-account-proof` requires its own
`CONTEXT_SELECTION_SOURCE` service ID and secret, with the exact customer RP in
`allowed_auth_clients`. Its identity is separate from the employee BFF source
service and the reverse `CUSTOMER_ACCESS_PROOF` service. Consumers call the
private HTTPS origin with its configured CA; the public gateway rejects the
route. Cookie and query authentication are rejected.

The exact JSON request uses `customer-account-proof-request/1`,
`oidcAccessToken` (the server-held opaque access token), and `expectedClientId`
(canonical UUIDv7). The client must be enabled, confidential, WEB_BFF, USER and
PLATFORM_CONTEXT; its application purpose is CUSTOMER_PORTAL and its only member
type is CUSTOMER. ACCOUNT_ONLY, employee, machine, ID and refresh tokens cannot
establish a customer BFF account proof. Online validation rechecks canonical
account/session, client/application, consent/group, token and context bindings.

The `customer-account-proof/1` response carries `issuer`, `clientId`,
`clientPurpose`, `contextMode`, `allowedMemberTypes`, `scope`, opaque `sub`,
internal `userId`, `globalSessionId`, `grantId`, decimal-string
`accountVersion`, `clientPolicyVersion`, `applicationProjectionVersion`,
`authTime`, `expiresAt` and `absoluteExpiresAt`. The BFF compares `sub` with
the validated ID Token and UserInfo; it obtains its internal ID only from
`userId`. The access deadline is the minimum original access/grant/SSO deadline;
the absolute deadline is the minimum original grant/SSO deadline. No current
account or renewed source replaces the grant's original tuple. Account display
fields used by the reverse resource proof come from the same locked validation
transaction and never include employee administrator flags or credentials.

Malformed requests return 400, invalid/retired token sources return 401,
wrong service purpose or unregistered client scope returns 403, and unavailable
dependencies return 503. Private responses are not cacheable. Neither proof
endpoint chooses a business member or completes the portal's cross-database
context transaction; the platform and portal retain those checks.

## Canonical private resource access proof

`POST /internal/identity/auth/resource-access-proof` uses a separate
`RESOURCE_ACCESS_PROOF` service identity. Its `allowed_auth_resources` lists
the exact `auth_resources.id` records it may verify. This is a private endpoint;
OAuth client credentials, employee/customer BFF source credentials and public
gateway access do not grant this service purpose.

The exact JSON request is:

```json
{"contractVersion":"resource-access-proof-request/1","token":"<opaque access token>","resource":"<registered resource_key>","scope":"<one registered scope>","audience":"<exact registered audience>"}
```

The resource and scope must be active and registered together, the audience
must match that resource, the service must have that resource allowlist entry,
and the current token must contain the requested scope on that same resource.
The caller cannot widen scope or use an arbitrary audience. Service status,
credential digest and resource admission are checked again before response.

The `resource-access-proof/1` response contains `issuer`,
`tokenUse: "access_token"`, `subjectMode`, internal `clientId`, caller OAuth
`applicationId`, `resource`, `audience`, the token's current scopes on that
resource, `expiresAt`, and `source`. The application ID identifies the calling
OAuth application; it is not the platform application owning the target API.
Versions are decimal strings.

For USER, the grant must be online PLATFORM_CONTEXT. ACCOUNT_ONLY and offline
grants are rejected. The response adds the opaque `sub`,
`source: {grantId, globalSessionId, userId, accountVersion,
clientPolicyVersion, applicationProjectionVersion, authTime, contextRef}` and
`context: {membershipId, memberType}`. The member ID is the original canonical
context selection; its type comes from the client's single allowed member type.
Identity does not read platform members, tenants or organizations and does not
invent an identity version. Expiry is the minimum access/grant/SSO deadline.

For MACHINE, the response has `credentialVersion` and only
`source: {grantId, clientPolicyVersion, applicationProjectionVersion}`. There is
no `sub`, user, global session, authentication time or business context. Expiry
is bounded by the token, grant and current credential expiry, including its
90-day maximum lifetime. Revoked source credentials fail closed.

Credential mode is established through canonical online token state, not a
string prefix. ID and refresh tokens are rejected. Malformed requests return
400, inactive or ineligible token sources return 401, unavailable resource or
scope admission returns 403, and dependency failures remain unavailable. Proof
responses are not cacheable. Resource APIs still enforce current business
membership, application permissions, actions and data ranges; this projection
does not grant those business permissions itself.

## Manual partner admission and controlled invitations

Partner review uses the independent `AUTH_REVIEW` service purpose and fixed
`GET/PUT /internal/identity/auth/review/applications/{applicationId}/{test|production}`
targets. GET returns only `applicationId`, `environment`, nullable
`projectionVersion`/`admissionVersion`, and `status`. PUT accepts exactly
`applicationId`, `environment`, `requestId`, `requestVersion`, `actorUserId`,
`actorSessionId`, nullable `expectedProjectionVersion`/`expectedAdmissionVersion`,
`partnerId`, `manifest`, `requestedBy`, `reviewedBy`, nullable `publishedBy`,
`contactReference`, `domainReference`, and `status: APPROVED|SUSPENDED`.
The strict manifest is documented in the [partner onboarding contract](../../saas-plateform/backend/docs/designs/unified-auth/phase-19-partner-onboarding.md).
The private service cannot invent approval facts: the platform-owned narrow
fence compares the entire payload with the current versioned application
request, original actor/session intent, immutable partner, independently
reviewed evidence and production responsibility bindings. It repeats the
canonical source, fine-permission, recent TOTP and application delegation checks
at commit. Conflicts cannot replace a newer proposal. The result contains the
exact request and resulting projection/admission versions. Original receipts
are read through `/internal/identity/auth/review-operations/{operationId}`.

`AUTH_INVITATION` protects GET/POST `/internal/identity/auth/invitations`,
GET `/{id}`, POST `/{id}/revoke`, and receipt lookup at
`/internal/identity/auth/invitation-operations/{operationId}`. Issue binds
`actorUserId`, `actorSessionId`, `recipientRef` and `purpose`; revoke binds the
same actor/session and `expectedVersion`. Platform intent and current TOTP/fine
permission are mandatory. Management responses contain metadata only, never
the token or its digest. Invitations expire 24 hours after issue; recipient
and purpose are immutable. A separate independent invitation keyset allows
the original material to be reconstructed without storing its plaintext.

`AUTH_INVITATION_KEYSET_PATH` is an absolute path to a bounded startup-loaded
JSON document with `purpose: "saas-identity/auth-invitation/1"`, a positive
`activeVersion`, and `keys: [{"version": 1, "key": "..."}]`. Each key is the
canonical unpadded-base64url encoding of 32 independent random bytes; an
all-zero key is rejected. Versions and material are unique. Keep an original version available while
its invitations or original-operation recovery still require it. Missing keys
or reuse of TOTP/service/client credential material fail closed.

Issuance also requires exactly one currently effective owner-controlled
`auth_delivery_targets` row with `purpose=VERIFIED_CHANNEL`,
`channel_purpose=ACCOUNT_ONBOARDING`, the exact `recipient_ref`, no client,
and a current verification/expiry. Missing or ambiguous channels fail closed.
The invitation, mandatory audit, management receipt and an `INVITATION`
delivery job are committed together. The job contains invitation/target IDs,
the target version and an event digest; it never contains a token.

After issuance, the trusted owner registers an
`auth_invitation_verifications` fact for that invitation. It binds the exact
recipient and `ACCOUNT_ONBOARDING` purpose, original job target/version,
independent verification evidence UUID, verification time and expiry. Runtime
can only read these facts. Narrow owner functions lock the exact current
target and verification versions; runtime receives EXECUTE for those fences
without gaining UPDATE on either fact table. A client-provided UUID cannot create a channel or a
verification fact, and there is no runtime HTTP endpoint to invent one.

The old `/{id}/delivery-material` and claim-only `/{id}/consume` HTTP routes
are closed. The delivery worker calls the process-local
`material_for_delivery(state, job_id, lease_id)` capability. It requires the
exact active job lease, an active unexpired invitation, the current target
generation and exactly one current owner verification fact. Missing or
ambiguous verification remains unavailable for bounded retry; revoked,
expired or mismatched authority is rejected. Material is reconstructed only
in memory and has no Debug/serialization implementation. The worker's
`verification_ref` is the actual verification **fact ID**;
`verified_channel_ref` is the registered delivery **target ID**. Neither
reference alone authorizes acceptance. Raw tokens do not enter management
responses, retry rows, receipts or audits. Target URLs and approved IPs come
only from owner-controlled target facts.

The worker's `acceptUrl` opens `GET /sso/invitations/{invitationId}`.
This no-store public shell validates the canonical UUIDv7 path but never reads
invitation existence, recipient, status or token. It uses the existing SSO
stylesheet and restrictive same-origin CSP. Query parameters are rejected.
The recipient manually enters the delivered token and actual `verificationRef`,
then chooses a new username and password. The page generates a cryptographically
random UUIDv7 operation ID and allows a previously saved original ID to be
pasted for recovery. The operation ID must be saved before submission.

The form posts JSON to the same-origin acceptance endpoint with credentials
omitted. Token and password never enter URLs, browser storage, history or logs;
the form clears them immediately on submission and when leaving the page.
Unknown results and failures keep the original operation ID and require manual
re-entry of the same original fields. Failure bodies are never displayed.
Success renders only `ACCOUNT_CREATED` and a link to `/sso/login`; the page
does not establish a session or redirect to an application.

The directed public acceptance endpoint is:

```http
POST /api/sso/invitations/{invitationId}/accept
Origin: https://auth.saas.test
Content-Type: application/json
```

```json
{
  "operationId": "canonical UUIDv7 saved before submitting",
  "token": "the 32-byte unpadded-base64url delivered invitation token",
  "username": "a new unique username",
  "password": "a password meeting the current account policy",
  "verificationRef": "the owner verification fact UUIDv7"
}
```

The endpoint requires the configured SSO origin, bounds request size and work,
rejects query parameters and extra authority fields, and returns no-store.
Cookies do not select or merge an existing account. It validates the token,
exact recipient/purpose/channel source, current fact/target generation and
absolute expiry before password work, releases all database locks while the
existing bounded password service hashes the password, then repeats the
source checks in the final transaction.

The final transaction inserts a fresh ordinary `users` account, immutable
`auth_invitation_activation_receipts`, consumes the invitation and writes its
mandatory audit. The receipt stores only source IDs/versions, the new account
ID, a purpose-separated HMAC request digest/key version, and this safe result:

```json
{"operationId":"original UUIDv7","invitationId":"invitation UUIDv7","status":"ACCOUNT_CREATED"}
```

The HMAC binds the original token and password without storing either value
or a password hash in the receipt. Repeating the exact original POST recovers
its result, including after a lost response or a later account disable. A
changed operation body conflicts and cannot overwrite credentials. A different
operation cannot consume the same invitation or verification again. Existing
usernames conflict regardless of account status; no account is re-enabled or
merged by email, and the recipient reference is not copied into email/phone
aliases. Creation adds no membership, business role, SSO session or OAuth
grant. The recipient may subsequently sign in through the normal SSO flow.

## Canonical RP logout and bounded delivery

The public confidential USER RP extension is `POST /oauth/logout`, using
`client_secret_basic` and form fields `token`, `scope` (`CURRENT_APP` or
`GLOBAL`), UUIDv7 `operation_id`, original opaque `sid` and pairwise `sub`.
An optional `client_id` must match Basic authentication. Cookies, queries,
duplicate and unknown fields are rejected. The fixed response contains only
`operationId`, `scope`, `state=COMPLETED`, `revokedGrantCount`,
`revokedSsoCount` and `notificationCount`. CURRENT_APP affects exactly the
original grant; GLOBAL affects every USER source for the original account.
Both preserve consent and never revoke another account or MACHINE source.

`POST /oauth/logout/operations/{operationId}` accepts the identical original
credentials and source tuple, with the body operation optional but matching
the path. A matching committed receipt can be recovered after the operation
revoked the original token. Only an explicit 404 JSON `code=NOT_FOUND` permits
re-sending the same original operation; uncertain responses never authorize a
new operation. Discovery names this extension `rp_logout_command_endpoint`.

`auth_rp_sessions` fixes immutable original grant/client/account/source and
public `sid`/`sub`. Grant, SSO/account, client-policy and consent invalidation
enqueue the same bounded `auth_delivery_jobs`; security source events fan
out only to owner-verified SECURITY recipients. Network calls run after the
authority transaction commits. Owner-only target and invitation facts remain
SELECT-only to runtime: narrow SECURITY DEFINER fences lock exact generations
and recheck database time without granting UPDATE merely for row locks.

Workers claim with SKIP LOCKED, at most four jobs per round, a fresh UUIDv7
lease and `jti` per attempt, 30-second leases, a three-second total transport
deadline, 60-second exponential retry capped at one hour, eight attempts and
a 24-hour total budget. 408/429/5xx and transport failures retry; redirect,
other permanent 4xx, expired/revoked or changed destinations terminate. Fixed
error codes and `identity_delivery_terminal` warnings support operations;
raw responses and credentials are never retained. Lease completion uses CAS,
so an old attempt cannot settle a replacement lease.

`AUTH_DELIVERY_WORKER_ENABLED` defaults false. `AUTH_DELIVERY_CA_FILE` is an
optional absolute CA file. `AUTH_DELIVERY_TEST_ORIGINS` permits only exact
HTTPS `.test` origins under APP_ENV=test; its presence in production rejects
startup. Every DNS answer must match owner-approved public IPs, with original
TLS hostname/SNI retained and no proxy, second DNS lookup or redirect. The
full receiver, registration and degradation contract is the
[Phase 20 contract](../../saas-plateform/backend/docs/designs/unified-auth/phase-20-logout-delivery-contract.md).

## Migration and readiness

The canonical platform migration job exclusively executes fresh baseline `0001`.
This service has no migrator, seed or automatic DDL. Normal startup reads the
provisioned `identity_deployment_state` and requires schema version 1,
the exact issuer and its configured runtime identity. A runtime must not be an
owner, superuser, owner-role member, schema creator or database creator. Account
DELETE, primary-key UPDATE and platform policy access are unavailable to it.

Receipt lookup and every OIDC management mutation acquire the same operation advisory transaction lock before reading the original receipt. A missing receipt remains UNKNOWN while its accepted intent is live or the authority is unavailable. Only after the platform's database clock proves the original 60-second intent has expired, and the synchronized lookup returns 404, may the platform report NOT_APPLIED. Recovery never re-dispatches the old mutation or password payload.
