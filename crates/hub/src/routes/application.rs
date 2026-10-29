//! The join application (join-forms.md): a form a joiner fills while seated
//! `pending`, which a moderator reads before approving or rejecting. It runs
//! on the survey engine (`survey.rs`) with `purpose = 'application'`.
//!
//! A rejected joiner stays `pending`, with the rejection on their response:
//! they may read why and apply again after a cooldown, and the approval queue
//! leaves them out until they do. Answers are personal data the joiner gave
//! one hub, so they are deleted a fixed time after the decision.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::survey::{
    self, SubmitSurveyRequest, SurveyAdmin, SurveyPublic, SurveyResponseAdmin, APPLICATION,
};
use crate::auth::middleware::AuthUser;
use crate::permissions::{self, HUB_ADMISSION, SURVEYS_MANAGE};
use crate::state::AppState;

/// How long a rejected applicant waits before applying again.
const REAPPLY_COOLDOWN_SECS: i64 = 7 * 24 * 3600;
/// How long answers are kept after the decision.
const RETENTION_SECS: i64 = 30 * 24 * 3600;

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

#[derive(Serialize)]
pub struct ApplicationStatus {
    /// `none` | `submitted` | `rejected`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix seconds from which a rejected applicant may apply again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<i64>,
}

#[derive(Deserialize)]
pub struct RejectRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct OwnResponse {
    id: String,
    rejected: bool,
    rejection_reason: Option<String>,
    decided_at: Option<i64>,
}

async fn own_response(
    db: &sqlx::PgPool,
    pubkey: &str,
) -> Result<Option<OwnResponse>, (StatusCode, String)> {
    sqlx::query_as(
        "SELECT sr.id, sr.rejected, sr.rejection_reason, sr.decided_at
         FROM survey_responses sr
         JOIN surveys s ON s.id = sr.survey_id AND s.purpose = 'application'
         WHERE sr.pubkey = $1
         ORDER BY sr.submitted_at DESC LIMIT 1",
    )
    .bind(pubkey)
    .fetch_optional(db)
    .await
    .map_err(db_err)
}

/// Whether the hub currently asks joiners to apply. An enabled application
/// seats every newcomer `pending`, whatever `require_approval` says.
pub async fn is_enabled(db: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM surveys WHERE purpose = 'application' AND enabled = TRUE)",
    )
    .fetch_one(db)
    .await
}

/// GET /application — public, so a client can show the form from an invite
/// link or a directory listing before the joiner has a seat here.
pub async fn get_application(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Option<SurveyPublic>>, (StatusCode, String)> {
    Ok(Json(
        survey::load_active_public(&state.db, APPLICATION).await?,
    ))
}

/// GET /application/status
pub async fn get_status(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<ApplicationStatus>, (StatusCode, String)> {
    Ok(Json(
        match own_response(&state.db, &user.public_key).await? {
            None => ApplicationStatus {
                state: "none",
                reason: None,
                retry_after: None,
            },
            Some(r) if r.rejected => ApplicationStatus {
                state: "rejected",
                reason: r.rejection_reason,
                retry_after: r.decided_at.map(|d| d + REAPPLY_COOLDOWN_SECS),
            },
            Some(_) => ApplicationStatus {
                state: "submitted",
                reason: None,
                retry_after: None,
            },
        },
    ))
}

/// POST /application
pub async fn submit(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SubmitSurveyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let form = survey::load_active_public(&state.db, APPLICATION)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            "This hub takes no applications".to_string(),
        ))?;
    if form.id != req.survey_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "survey_id does not match the hub's application".to_string(),
        ));
    }

    let status: Option<String> =
        sqlx::query_scalar("SELECT approval_status FROM users WHERE public_key = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    if status.as_deref() != Some("pending") {
        return Err((StatusCode::CONFLICT, "Already a member".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();
    if let Some(prev) = own_response(&state.db, &user.public_key).await? {
        if !prev.rejected {
            return Err((
                StatusCode::CONFLICT,
                "Application already submitted".to_string(),
            ));
        }
        let retry_after = prev.decided_at.unwrap_or(now) + REAPPLY_COOLDOWN_SECS;
        if now < retry_after {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("retry_after:{retry_after}"),
            ));
        }
        // A new application replaces the rejected one; its answers go with it.
        sqlx::query("DELETE FROM survey_responses WHERE id = $1")
            .bind(&prev.id)
            .execute(&state.db)
            .await
            .map_err(db_err)?;
    }

    survey::validate_answers(&form, &req.answers)?;

    let response_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO survey_responses (id, pubkey, survey_id, submitted_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&response_id)
    .bind(&user.public_key)
    .bind(&form.id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    survey::store_answers(&state.db, &response_id, &req.answers).await?;

    Ok(StatusCode::CREATED)
}

/// GET /admin/application
pub async fn admin_get(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Option<SurveyAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(SURVEYS_MANAGE)?;
    Ok(Json(survey::admin_get_form(&state.db, APPLICATION).await?))
}

/// PUT /admin/application
pub async fn admin_put(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SurveyAdmin>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(SURVEYS_MANAGE)?;
    survey::admin_put_form(&state, &perms, APPLICATION, &req).await?;
    Ok(StatusCode::OK)
}

/// GET /admin/application/responses/{pubkey} — readable by whoever decides
/// admission, and nobody else: these are a joiner's answers to one question,
/// "should we let you in".
pub async fn admin_get_response(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<Option<SurveyResponseAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_ADMISSION)?;
    Ok(Json(
        survey::latest_response(&state.db, &pubkey, APPLICATION).await?,
    ))
}

/// POST /hub/pending/{pubkey}/reject
pub async fn reject(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<RejectRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_ADMISSION)?;

    let now = crate::auth::handlers::unix_timestamp();
    let updated = sqlx::query(
        "UPDATE survey_responses SET rejected = TRUE, decided_at = $2, rejection_reason = $3
         WHERE id = (
             SELECT sr.id FROM survey_responses sr
             JOIN surveys s ON s.id = sr.survey_id AND s.purpose = 'application'
             JOIN users u ON u.public_key = sr.pubkey AND u.approval_status = 'pending'
             WHERE sr.pubkey = $1 AND sr.rejected = FALSE
             ORDER BY sr.submitted_at DESC LIMIT 1
         )",
    )
    .bind(&pubkey)
    .bind(now)
    .bind(
        req.reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty()),
    )
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "No pending application from this identity".to_string(),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// On approval, start the answers' deletion clock.
pub async fn mark_approved(db: &sqlx::PgPool, pubkey: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE survey_responses SET decided_at = $2
         WHERE pubkey = $1 AND decided_at IS NULL
           AND survey_id IN (SELECT id FROM surveys WHERE purpose = 'application')",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

/// Delete application answers whose decision is older than the window.
pub async fn sweep(db: &sqlx::PgPool, now: i64) {
    if let Err(e) = sqlx::query(
        "DELETE FROM survey_responses
         WHERE decided_at <= $1
           AND survey_id IN (SELECT id FROM surveys WHERE purpose = 'application')",
    )
    .bind(now - RETENTION_SECS)
    .execute(db)
    .await
    {
        tracing::warn!("application sweep failed: {e}");
    }
}
