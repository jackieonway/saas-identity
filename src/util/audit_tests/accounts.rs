use anyhow::{ensure, Result};
use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use super::Database;

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE08_TEST_MARKER and IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase13_created_account_starts_at_generation_one_and_recovers_the_same_receipt(
) -> Result<()> {
    let database = Database::create_phase08().await?;
    let result = async {
        // Exercise the actual private CREATE handler against the former default.
        // This narrow persistence fixture does not replace the canonical-schema,
        // real runtime-role and SSO/OAuth browser regression.
        sqlx::query("ALTER TABLE public.users ALTER COLUMN session_version SET DEFAULT 0")
            .execute(&database.pool).await?;
        let target = Uuid::now_v7();
        let operation = Uuid::now_v7();
        let reply = database.account_call(operation,target,0,"CREATE",json!({
            "username":format!("fresh-account-{}",target.simple()),
            "realName":"Fresh account", "email":"", "phone":"", "gender":"UNKNOWN",
            "password":"Synthetic-owned-account-password-83!"
        })).await?;
        ensure!(reply.status == StatusCode::OK,"private CREATE failed before returning its receipt");
        ensure!(reply.body["beforeVersion"]=="0" && reply.body["afterVersion"]=="1",
            "CREATE must use generation zero only as the missing-account precondition and commit generation one");
        let actual: i64 = sqlx::query_scalar("SELECT session_version FROM users WHERE id=$1")
            .bind(target).fetch_one(&database.pool).await?;
        ensure!(actual==1,"new account retained an unusable zero generation");
        let digest = reply.body["canonicalDigest"].as_str()
            .ok_or_else(|| anyhow::anyhow!("CREATE receipt omitted its digest"))?;
        let recovered = database.call("ACCOUNT_COMMAND","GET",
            &format!("/internal/identity/accounts/operations/{operation}?digest={digest}"),None,&[]).await?;
        ensure!(recovered.status==StatusCode::OK && recovered.body==reply.body,
            "original CREATE operation did not recover its exact generation-one receipt");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id=$1")
            .bind(target).fetch_one(&database.pool).await?;
        ensure!(count==1,"CREATE recovery created another account");
        Ok(())
    }.await;
    database.finish(result).await
}

// Password material remains internal even when a rollback assertion fails: this
// snapshot deliberately has no Debug implementation and errors print no values.
struct AccountState {
    snapshot: (i64, String, i64, i64, i64),
    password_hash: String,
    facts: Vec<(i64, i64)>,
}

impl AccountState {
    async fn read(database: &Database) -> Result<Self> {
        let snapshot = database.snapshot().await?;
        let password_hash =
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM public.users WHERE id=$1")
                .bind(database.user)
                .fetch_one(&database.pool)
                .await?;
        let facts = sqlx::query_as::<_, (i64, i64)>(
            "SELECT account_version,platform_session_count \
             FROM public.identity_account_revocation_facts WHERE user_id=$1 ORDER BY account_version",
        )
        .bind(database.user)
        .fetch_all(&database.pool)
        .await?;
        Ok(Self {
            snapshot,
            password_hash,
            facts,
        })
    }

    fn require_unchanged(&self, after: &Self, kind: &str) -> Result<()> {
        ensure!(
            self.snapshot == after.snapshot,
            "{kind}: suppressed write changed account version/status, audit, receipt or tombstone"
        );
        ensure!(
            self.password_hash == after.password_hash,
            "{kind}: suppressed write changed password material"
        );
        ensure!(
            self.facts == after.facts,
            "{kind}: suppressed write changed generation revocation facts"
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase12_account_required_writes_and_receipt_suppression_roll_back() -> Result<()> {
    let database = Database::create().await?;
    let result = exercise(&database).await;
    database.finish(result).await
}

async fn exercise(database: &Database) -> Result<()> {
    // Establish a committed production-path result before testing suppression.
    // The HTTP helper signs the real command and dispatches accounts::routes().
    let before = AccountState::read(database).await?;
    ensure!(before.snapshot.0 == 1, "fixture account generation changed");
    ensure!(
        before.snapshot.1 == "ENABLED",
        "fixture account must start enabled"
    );
    let operation = Uuid::now_v7();
    let positive = database
        .account_call(
            operation,
            database.user,
            before.snapshot.0,
            "REVOKE_ALL",
            json!({}),
        )
        .await?;
    ensure!(
        positive.status == StatusCode::OK,
        "real REVOKE_ALL positive control returned {}",
        positive.status.as_u16()
    );
    ensure!(
        positive.body["state"] == "COMPLETED",
        "positive control did not return a completed receipt"
    );
    ensure!(
        positive.body["operationId"] == operation.to_string(),
        "positive control returned another operation"
    );
    let after = AccountState::read(database).await?;
    ensure!(
        after.snapshot.0 == before.snapshot.0 + 1,
        "positive control did not increase the original account generation once"
    );
    ensure!(
        after.snapshot.1 == before.snapshot.1,
        "positive control unexpectedly changed account status"
    );
    ensure!(
        after.snapshot.2 == before.snapshot.2 + 1
            && after.snapshot.3 == before.snapshot.3 + 1
            && after.snapshot.4 == before.snapshot.4,
        "positive control did not atomically commit one audit and one receipt"
    );
    let fact = after
        .facts
        .iter()
        .find(|(generation, _)| *generation == after.snapshot.0)
        .ok_or_else(|| anyhow::anyhow!("positive control has no exact new-generation fact"))?;
    ensure!(
        positive.body["beforeVersion"]
            .as_str()
            .and_then(|value| value.parse::<i64>().ok())
            == Some(before.snapshot.0)
            && positive.body["afterVersion"]
                .as_str()
                .and_then(|value| value.parse::<i64>().ok())
                == Some(after.snapshot.0),
        "positive control receipt did not preserve exact generation strings"
    );
    ensure!(
        positive.body["revokedSessions"].as_i64() == Some(fact.1)
            && positive.body["revokedTokens"].as_i64() == Some(0),
        "positive control receipt did not use its exact bridge fact"
    );

    let expected = after.snapshot.0;
    suppressed(
        database,
        "identity_account_command_receipts",
        "INSERT",
        "REVOKE_ALL",
        json!({}),
        database.user,
        expected,
    )
    .await?;

    // RESET_PASSWORD and CHANGE_PASSWORD use the same required users UPDATE;
    // RESET exercises that production SQL without inventing a personal context.
    for (kind, payload) in [
        ("UPDATE_PROFILE", json!({"realName": "suppressed-profile"})),
        ("SET_STATUS", json!({"status": "DISABLED"})),
        (
            "RESET_PASSWORD",
            json!({"newPassword": "owned-new-password-for-test"}),
        ),
        ("REVOKE_ALL", json!({})),
        ("RETIRE", json!({})),
    ] {
        suppressed(
            database,
            "users",
            "UPDATE",
            kind,
            payload,
            database.user,
            expected,
        )
        .await?;
    }

    suppressed(
        database,
        "identity_account_tombstones",
        "INSERT",
        "RETIRE",
        json!({}),
        database.user,
        expected,
    )
    .await?;

    let target = Uuid::now_v7();
    suppressed(
        database,
        "users",
        "INSERT",
        "CREATE",
        json!({
            "username": "owned-suppressed-account",
            "realName": "Owned fixture",
            "email": "",
            "phone": "",
            "gender": "UNKNOWN",
            "password": "owned-new-password-for-test"
        }),
        target,
        0,
    )
    .await?;
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.users WHERE id=$1)")
        .bind(target)
        .fetch_one(&database.pool)
        .await?;
    ensure!(!present, "suppressed CREATE left its new target account");
    Ok(())
}

async fn suppressed(
    database: &Database,
    table: &str,
    event: &str,
    kind: &str,
    payload: Value,
    target: Uuid,
    expected: i64,
) -> Result<()> {
    let before = AccountState::read(database).await?;
    let operation = Uuid::now_v7();
    database.suppress(table, event).await?;
    let request = database
        .account_call(operation, target, expected, kind, payload)
        .await;
    // Remove the adversarial trigger even if dispatch itself failed. The outer
    // finish call still owns final cleanup of this explicitly marked fresh DB.
    let cleanup = database.unsuppress(table).await;
    let reply = request?;
    cleanup?;
    ensure!(
        reply.status == StatusCode::SERVICE_UNAVAILABLE,
        "{kind}: {table} {event} suppression returned {} instead of 503",
        reply.status.as_u16()
    );
    ensure!(
        reply.body["code"] == "SERVICE_UNAVAILABLE",
        "{kind}: suppression did not use the unavailable business wire"
    );
    let after = AccountState::read(database).await?;
    before.require_unchanged(&after, kind)?;
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.identity_account_command_receipts WHERE operation_id=$1)",
    )
    .bind(operation)
    .fetch_one(&database.pool)
    .await?;
    ensure!(
        !present,
        "{kind}: failed required write left a durable success receipt"
    );
    Ok(())
}
