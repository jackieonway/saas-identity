use super::Database;
use anyhow::{ensure, Result};
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::{
    error::AppError,
    oidc::subjects::{self, OidcProfile},
    sso::AccountSessionProof,
};

fn proof(user_id: Uuid, username: &str, expires_at: chrono::DateTime<Utc>) -> AccountSessionProof {
    AccountSessionProof {
        id: Uuid::now_v7(),
        user_id,
        account_version: 1,
        authenticated_at: Utc::now(),
        expires_at,
        username: username.to_owned(),
        real_name: "stale proof name".into(),
    }
}

async fn app(
    db: &Database,
    id: Uuid,
    ownership: &str,
    partner: Option<Uuid>,
    status: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO auth_applications(application_id,partner_id,ownership,status,display_name,purpose,approved_scopes,projection_version,projected_at) \
         VALUES($1,$2,$3,$4,'Subject fixture','Account login',ARRAY['openid','profile'],1,clock_timestamp())",
    )
    .bind(id)
    .bind(partner)
    .bind(ownership)
    .bind(status)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn client(
    db: &Database,
    id: Uuid,
    application: Uuid,
    environment: &str,
    subject: &str,
) -> Result<()> {
    let (client_type, runtime, context, auth_method, redirect) = if subject == "MACHINE" {
        (
            "CONFIDENTIAL",
            "SERVICE",
            "NONE",
            "client_secret_basic",
            "{}",
        )
    } else {
        (
            "PUBLIC",
            "SPA",
            "ACCOUNT_ONLY",
            "none",
            "{\"https://client.example.test/callback\"}",
        )
    };
    let redirect_uris: Vec<String> = if redirect == "{}" {
        vec![]
    } else {
        vec!["https://client.example.test/callback".into()]
    };
    let grants: Vec<String> = if subject == "MACHINE" {
        vec!["client_credentials".into()]
    } else {
        vec!["authorization_code".into()]
    };
    sqlx::query(
        "INSERT INTO auth_clients(id,client_id,display_name,application_id,environment,client_type,runtime_kind,subject_mode,context_mode, \
         allowed_member_types,grant_types,token_endpoint_auth_method,redirect_uris,post_logout_redirect_uris,status,version,policy_version,created_at,updated_at) \
         VALUES($1,$2,'Subject fixture client',$3,$4,$5,$6,$7,$8,ARRAY[]::text[],$9,$10,$11,ARRAY[]::text[],'ENABLED',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(id)
    .bind(format!("subject-client-{id}"))
    .bind(application)
    .bind(environment)
    .bind(client_type)
    .bind(runtime)
    .bind(subject)
    .bind(context)
    .bind(grants)
    .bind(auth_method)
    .bind(redirect_uris)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn account(db: &Database, id: Uuid, username: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,real_name,email,phone,avatar) \
         VALUES($1,$2,'unusable-subject-fixture','Fixture Name','fixture@example.test','+15550000000','https://cdn.example.test/fixture.png')",
    )
    .bind(id)
    .bind(username)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn resolve(
    db: &Database,
    proof: &AccountSessionProof,
    client: Uuid,
) -> Result<OidcProfile, AppError> {
    let mut tx = db.pool.begin().await.map_err(AppError::from)?;
    let result = subjects::profile_for_client(&mut tx, proof, client).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires explicit task-owned IDENTITY_PHASE12_TEST_DATABASE_URL"]
async fn phase06_pairwise_subjects_are_sector_scoped_stable_and_retired_with_accounts() -> Result<()>
{
    let db = Database::create_phase04().await?;
    let result = exercise(&db).await;
    db.finish(result).await
}

async fn exercise(db: &Database) -> Result<()> {
    let platform_app = Uuid::now_v7();
    let partner_app = Uuid::now_v7();
    let draft_app = Uuid::now_v7();
    let concurrent_app = Uuid::now_v7();
    let partner = Uuid::now_v7();
    app(db, platform_app, "FIRST_PARTY", None, "APPROVED").await?;
    // This approved projection is a database fixture; the Q3/Phase 19 review
    // service remains the only path that may approve a real partner app.
    app(db, partner_app, "THIRD_PARTY", Some(partner), "APPROVED").await?;
    app(
        db,
        draft_app,
        "THIRD_PARTY",
        Some(Uuid::now_v7()),
        "PENDING_REVIEW",
    )
    .await?;
    app(db, concurrent_app, "FIRST_PARTY", None, "APPROVED").await?;

    let same_sector_client = Uuid::now_v7();
    let sibling_client = Uuid::now_v7();
    let other_environment_client = Uuid::now_v7();
    let other_application_client = Uuid::now_v7();
    let unreviewed_client = Uuid::now_v7();
    let machine_client = Uuid::now_v7();
    let concurrent_client = Uuid::now_v7();
    client(db, same_sector_client, platform_app, "production", "USER").await?;
    client(db, sibling_client, platform_app, "production", "USER").await?;
    client(db, other_environment_client, platform_app, "test", "USER").await?;
    client(
        db,
        other_application_client,
        partner_app,
        "production",
        "USER",
    )
    .await?;
    client(db, unreviewed_client, draft_app, "production", "USER").await?;
    client(db, machine_client, platform_app, "production", "MACHINE").await?;
    client(db, concurrent_client, concurrent_app, "production", "USER").await?;

    let original_user = db.user;
    let second_user = Uuid::now_v7();
    let replacement_user = Uuid::now_v7();
    let concurrent_user = Uuid::now_v7();
    account(db, second_user, "subject-isolation-account").await?;
    account(db, replacement_user, "subject-replacement-account").await?;
    account(db, concurrent_user, "subject-concurrent-account").await?;
    sqlx::query("UPDATE users SET real_name='Current Display Name',email='private@example.test',phone='+15551112222',avatar='https://cdn.example.test/current.png' WHERE id=$1")
        .bind(original_user).execute(&db.pool).await?;
    let expiry = Utc::now() + Duration::hours(1);
    let original_proof = proof(original_user, "stale-username", expiry);
    let second_proof = proof(second_user, "other-username", expiry);
    let concurrent_proof = proof(concurrent_user, "concurrent-username", expiry);

    // Two requests race to create both the application/environment sector and
    // the first account link. They must converge on one persisted public sub.
    let (concurrent_left, concurrent_right) = tokio::join!(
        resolve(db, &concurrent_proof, concurrent_client),
        resolve(db, &concurrent_proof, concurrent_client),
    );
    let concurrent_left = concurrent_left?;
    let concurrent_right = concurrent_right?;
    let left_sub = concurrent_left.userinfo_claims(&["openid".into()])?["sub"].clone();
    let right_sub = concurrent_right.userinfo_claims(&["openid".into()])?["sub"].clone();
    let concurrent_rows: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_subject_sectors WHERE application_id=$1 AND environment='production'), \
         (SELECT count(*) FROM auth_subject_links WHERE user_id=$2)",
    )
    .bind(concurrent_app)
    .bind(concurrent_user)
    .fetch_one(&db.pool)
    .await?;
    ensure!(
        left_sub == right_sub && concurrent_rows == (1, 1),
        "concurrent subject creation did not converge on one sector and one link"
    );

    let first = resolve(db, &original_proof, same_sector_client).await?;
    let same_sector = resolve(db, &original_proof, sibling_client).await?;
    let other_environment = resolve(db, &original_proof, other_environment_client).await?;
    let other_application = resolve(db, &original_proof, other_application_client).await?;
    let other_account = resolve(db, &second_proof, same_sector_client).await?;
    let first_claims = first.userinfo_claims(&["openid".into(), "profile".into()])?;
    ensure!(
        first_claims["sub"]
            == same_sector.userinfo_claims(&["openid".into(), "profile".into()])?["sub"],
        "same application/environment clients did not share a stable subject"
    );
    ensure!(
        first_claims["sub"] != other_environment.userinfo_claims(&["openid".into()])?["sub"]
            && first_claims["sub"] != other_application.userinfo_claims(&["openid".into()])?["sub"],
        "different sectors received the same pairwise subject"
    );
    ensure!(
        first_claims["sub"] != other_account.userinfo_claims(&["openid".into()])?["sub"],
        "different users received the same pairwise subject"
    );
    ensure!(
        first_claims["sub"] != json!(original_user.to_string()),
        "public subject disclosed the internal account UUID"
    );

    let id_token_claims = first.id_token_claims(&["openid".into(), "profile".into()])?;
    ensure!(
        id_token_claims["sub"] == first_claims["sub"]
            && id_token_claims["name"] == "Current Display Name"
            && id_token_claims["picture"] == "https://cdn.example.test/current.png",
        "ID Token projection diverged from the trusted current profile"
    );
    ensure!(
        first_claims["name"] == "Current Display Name"
            && first_claims["picture"] == "https://cdn.example.test/current.png",
        "profile projection did not read current trusted account data"
    );
    for forbidden in [
        "userId",
        "user_id",
        "preferred_username",
        "email",
        "email_verified",
        "phone_number",
        "phone_number_verified",
        "roles",
    ] {
        ensure!(
            first_claims.get(forbidden).is_none(),
            "public profile included forbidden field {forbidden}"
        );
    }
    let account_only = first.userinfo_claims(&["openid".into()])?;
    ensure!(
        account_only
            .as_object()
            .is_some_and(|claims| claims.len() == 1 && claims.contains_key("sub")),
        "profile fields were returned without a consented profile scope"
    );
    ensure!(
        first.userinfo_claims(&["profile".into()]).is_err(),
        "OIDC claims were constructed without openid scope"
    );

    // A subject is random persisted state, not a derivation from display data
    // or signing material. Account rename and signing key rotation keep it.
    sqlx::query("UPDATE users SET real_name='Renamed Display Name',avatar='https://cdn.example.test/renamed.png' WHERE id=$1")
        .bind(original_user).execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_signing_keys(kid,n,e,published_at,active,activated_at) VALUES('subject-old-key','n-old','e-old',clock_timestamp(),true,clock_timestamp())")
        .execute(&db.pool).await?;
    sqlx::query("UPDATE auth_signing_keys SET active=false,retired_at=clock_timestamp() WHERE kid='subject-old-key'")
        .execute(&db.pool).await?;
    sqlx::query("INSERT INTO auth_signing_keys(kid,n,e,published_at,active,activated_at) VALUES('subject-new-key','n-new','e-new',clock_timestamp(),true,clock_timestamp())")
        .execute(&db.pool).await?;
    let renamed = resolve(db, &original_proof, same_sector_client).await?;
    let renamed_claims = renamed.id_token_claims(&["openid".into(), "profile".into()])?;
    ensure!(
        renamed_claims["sub"] == first_claims["sub"]
            && renamed_claims["name"] == "Renamed Display Name"
            && renamed_claims["picture"] == "https://cdn.example.test/renamed.png",
        "account rename or signing-key rotation changed the persisted subject"
    );
    sqlx::query("UPDATE users SET avatar='http://cdn.example.test/insecure.png' WHERE id=$1")
        .bind(original_user)
        .execute(&db.pool)
        .await?;
    let unsafe_picture = resolve(db, &original_proof, same_sector_client)
        .await?
        .userinfo_claims(&["openid".into(), "profile".into()])?;
    ensure!(
        unsafe_picture.get("picture").is_none(),
        "non-HTTPS avatar was projected as picture"
    );

    let unreviewed = resolve(db, &original_proof, unreviewed_client).await;
    ensure!(
        matches!(unreviewed, Err(AppError::Forbidden(_))),
        "unreviewed application received a subject sector"
    );
    let machine = resolve(db, &original_proof, machine_client).await;
    ensure!(
        matches!(machine, Err(AppError::Forbidden(_))),
        "MACHINE client received a user subject"
    );
    let draft_sectors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_subject_sectors WHERE application_id=$1")
            .bind(draft_app)
            .fetch_one(&db.pool)
            .await?;
    ensure!(
        draft_sectors == 0,
        "unreviewed application caused sector creation"
    );

    let retired = db
        .account_call(Uuid::now_v7(), original_user, 1, "RETIRE", json!({}))
        .await?;
    ensure!(
        retired.status == StatusCode::OK && retired.body["state"] == "COMPLETED",
        "account retirement did not commit through the identity command path"
    );
    let retired_links: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_subject_links WHERE user_id=$1 AND retired_at IS NOT NULL",
    )
    .bind(original_user)
    .fetch_one(&db.pool)
    .await?;
    ensure!(
        retired_links == 3,
        "retirement did not permanently retire every issued subject link"
    );
    let old_account = resolve(db, &original_proof, same_sector_client).await;
    ensure!(
        matches!(old_account, Err(AppError::Unauthorized(_))),
        "retired account still resolved a public subject"
    );

    let replacement_proof = proof(replacement_user, "replacement-user", expiry);
    let replacement = resolve(db, &replacement_proof, same_sector_client).await?;
    let replacement_sub = replacement.userinfo_claims(&["openid".into()])?["sub"].clone();
    ensure!(
        replacement_sub != first_claims["sub"]
            && replacement_sub != other_account.userinfo_claims(&["openid".into()])?["sub"],
        "replacement account inherited a previous account's subject"
    );

    sqlx::query("UPDATE auth_subject_sectors SET status='RETIRED' WHERE application_id=$1 AND environment='production'")
        .bind(platform_app).execute(&db.pool).await?;
    let retired_sector = resolve(db, &replacement_proof, sibling_client).await;
    ensure!(
        matches!(retired_sector, Err(AppError::Forbidden(_))),
        "retired sector was silently recreated"
    );

    Ok(())
}
