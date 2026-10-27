//! Durable account-to-application approval, independent of SSO/token lifetime.
use crate::error::AppError;
use sqlx::PgConnection;
use uuid::Uuid;

pub(super) async fn approved(
    connection: &mut PgConnection,
    user: Uuid,
    client: Uuid,
    scopes: &[String],
) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oidc_consents WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL AND scopes @> $3::text[])")
        .bind(user).bind(client).bind(scopes).fetch_one(connection).await.map_err(Into::into)
}

pub(super) async fn save(
    connection: &mut PgConnection,
    user: Uuid,
    client: Uuid,
    scopes: &[String],
) -> Result<(), AppError> {
    // Callers serialize with the same account lock as explicit revocation.
    sqlx::query("INSERT INTO oidc_consents(user_id,client_id,scopes,approved_at) VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(user_id,client_id) DO UPDATE SET scopes=CASE WHEN oidc_consents.revoked_at IS NULL THEN ARRAY(SELECT DISTINCT unnest(oidc_consents.scopes || EXCLUDED.scopes) ORDER BY 1) ELSE EXCLUDED.scopes END,approved_at=EXCLUDED.approved_at,revoked_at=NULL")
        .bind(user).bind(client).bind(scopes).execute(connection).await?;
    Ok(())
}
