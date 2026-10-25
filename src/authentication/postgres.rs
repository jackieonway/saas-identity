//! PostgreSQL account storage with caller-owned transaction composition.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::AppError;
use crate::platform_accounts::{
    AccountCredential, AccountFuture, AccountMutationTx, AccountSnapshot, CredentialHash,
    LoginIdentifier, PreparedPassword,
};

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: Uuid,
    username: String,
    password_hash: String,
    status: String,
    session_version: i64,
    real_name: String,
}

impl From<CredentialRow> for AccountCredential {
    fn from(row: CredentialRow) -> Self {
        Self::new(
            row.id,
            row.username,
            row.real_name,
            row.status,
            row.session_version,
            CredentialHash::new(row.password_hash),
        )
    }
}

pub(super) async fn candidates(
    pool: &PgPool,
    identifier: LoginIdentifier<'_>,
) -> Result<Vec<AccountCredential>, AppError> {
    let rows: Vec<CredentialRow> = sqlx::query_as(
        "SELECT id, username, password_hash, status, session_version, COALESCE(real_name,'') AS real_name \
         FROM users WHERE username=$1 OR ($2<>'' AND regexp_replace(phone, '[[:space:]()\\-]', '', 'g')=$2) \
         OR ($3<>'' AND lower(email)=$3) ORDER BY id LIMIT 65",
    )
    .bind(identifier.identifier)
    .bind(identifier.phone)
    .bind(identifier.email)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::Unavailable)?;
    Ok(rows.into_iter().map(AccountCredential::from).collect())
}

pub(super) async fn by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AccountCredential>, AppError> {
    let row: Option<CredentialRow> = sqlx::query_as(
        "SELECT id, username, password_hash, status, session_version, COALESCE(real_name,'') AS real_name \
         FROM users WHERE username=$1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(AccountCredential::from))
}

pub(super) async fn by_user_id(pool: &PgPool, id: Uuid) -> Result<AccountCredential, AppError> {
    let row: CredentialRow = sqlx::query_as(
        "SELECT id, username, password_hash, status, session_version, COALESCE(real_name,'') AS real_name \
         FROM users WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(row.into())
}

/// Borrows the caller's connection without starting or committing a transaction.
/// The caller supplies its existing transaction connection and retains all
/// authentication audit and final commit.
pub(crate) struct PostgresAccountTransaction<'a> {
    connection: &'a mut PgConnection,
}

impl<'a> PostgresAccountTransaction<'a> {
    pub(crate) fn new(connection: &'a mut PgConnection) -> Self {
        Self { connection }
    }
}

impl AccountMutationTx for PostgresAccountTransaction<'_> {
    fn lock_account(&mut self, id: Uuid) -> AccountFuture<'_, AccountSnapshot> {
        Box::pin(async move {
            let (id, account_version, encoded): (Uuid, i64, String) = sqlx::query_as(
                "SELECT id,session_version,password_hash FROM users WHERE id=$1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut *self.connection)
            .await?
            .ok_or_else(|| AppError::not_found("用户不存在"))?;
            Ok(AccountSnapshot {
                id,
                account_version,
                credential: CredentialHash::new(encoded),
            })
        })
    }

    fn credential_matches<'a>(
        &'a mut self,
        credential: &'a AccountCredential,
    ) -> AccountFuture<'a, bool> {
        Box::pin(async move {
            // The caller already holds the original user-first issuance lock.
            // Capture the current account version later with membership policy;
            // a kick alone did not previously reject a freshly verified login.
            let current: Option<(String, String)> =
                sqlx::query_as("SELECT password_hash,status FROM users WHERE id=$1")
                    .bind(credential.id)
                    .fetch_optional(&mut *self.connection)
                    .await?;
            Ok(current.is_some_and(|(encoded, status)| {
                encoded == credential.credential().encoded() && status == "ENABLED"
            }))
        })
    }

    fn revoke_all<'a>(
        &'a mut self,
        id: Uuid,
        password: Option<&'a PreparedPassword>,
    ) -> AccountFuture<'a, u64> {
        Box::pin(async move {
            revoke_account(
                &mut *self.connection,
                id,
                password.map(PreparedPassword::encoded),
            )
            .await
        })
    }

    fn account_version(&mut self, id: Uuid) -> AccountFuture<'_, i64> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT session_version FROM users WHERE id=$1")
                .bind(id)
                .fetch_optional(&mut *self.connection)
                .await?
                .ok_or_else(|| AppError::not_found("用户不存在"))
        })
    }
}

async fn revoke_account(
    connection: &mut PgConnection,
    id: Uuid,
    new_password_hash: Option<&str>,
) -> Result<u64, AppError> {
    let subject: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *connection)
        .await?;
    if subject.is_none() {
        return Err(AppError::not_found("用户不存在"));
    }
    // Only authentication tables are read here. The canonical migration installs
    // a constrained trigger bridge for synchronous platform credential denial.
    let updated = sqlx::query("UPDATE users SET session_version=session_version+1,password_hash=COALESCE($2,password_hash),updated_at=clock_timestamp() WHERE id=$1")
        .bind(id).bind(new_password_hash).execute(&mut *connection).await?.rows_affected();
    if updated != 1 {
        return Err(AppError::not_found("账号不存在"));
    }
    let revoked:i64=sqlx::query_scalar("SELECT f.platform_session_count FROM identity_account_revocation_facts f JOIN users u ON u.id=f.user_id AND u.session_version=f.account_version WHERE f.user_id=$1")
        .bind(id).fetch_optional(&mut *connection).await?.ok_or(AppError::Unavailable)?;
    let revoked = u64::try_from(revoked).map_err(|_| AppError::Unavailable)?;
    Ok(revoked)
}
