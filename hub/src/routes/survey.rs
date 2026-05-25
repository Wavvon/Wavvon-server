use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Public-facing types (no role mappings)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct SurveyChoicePublic {
    pub id: String,
    pub label: String,
    pub display_order: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SurveyQuestionPublic {
    pub id: String,
    pub prompt: String,
    pub kind: String,
    pub required: bool,
    pub display_order: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<SurveyChoicePublic>>,
}

#[derive(Serialize, Deserialize)]
pub struct SurveyPublic {
    pub id: String,
    pub questions: Vec<SurveyQuestionPublic>,
}

// ---------------------------------------------------------------------------
// Admin types (includes role mappings)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct SurveyChoiceAdmin {
    pub id: String,
    pub label: String,
    pub display_order: i64,
    pub role_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SurveyQuestionAdmin {
    pub id: String,
    pub prompt: String,
    pub kind: String,
    pub required: bool,
    pub display_order: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<SurveyChoiceAdmin>>,
}

#[derive(Serialize, Deserialize)]
pub struct SurveyAdmin {
    pub id: String,
    pub enabled: bool,
    pub questions: Vec<SurveyQuestionAdmin>,
}

// ---------------------------------------------------------------------------
// Submit request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SurveyAnswerInput {
    pub question_id: String,
    pub choice_id: Option<String>,
    pub text_answer: Option<String>,
}

#[derive(Deserialize)]
pub struct SubmitSurveyRequest {
    pub survey_id: String,
    pub answers: Vec<SurveyAnswerInput>,
}

#[derive(Serialize)]
pub struct SubmitSurveyResponse {
    pub next_state: String,
    pub applied_roles: Vec<String>,
}

// ---------------------------------------------------------------------------
// Admin response list types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SurveyAnswerView {
    pub question_id: String,
    pub prompt: String,
    pub choice_label: Option<String>,
    pub text_answer: Option<String>,
}

#[derive(Serialize)]
pub struct SurveyResponseAdmin {
    pub response_id: String,
    pub pubkey: String,
    pub display_name: Option<String>,
    pub submitted_at: i64,
    pub answers: Vec<SurveyAnswerView>,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ResponsesQuery {
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub cursor: Option<String>,
}

fn default_status() -> String {
    "pending".to_string()
}

fn default_limit() -> i64 {
    50
}

// ---------------------------------------------------------------------------
// SQLx row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct SurveyRow {
    id: String,
    enabled: i64,
}

#[derive(sqlx::FromRow)]
struct QuestionRow {
    id: String,
    prompt: String,
    kind: String,
    required: i64,
    display_order: i64,
}

#[derive(sqlx::FromRow)]
struct ChoiceRow {
    id: String,
    label: String,
    display_order: i64,
}

#[derive(sqlx::FromRow)]
struct ResponseRow {
    id: String,
    pubkey: String,
    display_name: Option<String>,
    submitted_at: i64,
}

#[derive(sqlx::FromRow)]
struct AnswerRow {
    question_id: String,
    prompt: String,
    choice_label: Option<String>,
    text_answer: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the active survey (enabled=1) with all questions and choices,
/// without role mappings.
async fn load_active_survey_public(
    db: &sqlx::SqlitePool,
) -> Result<Option<SurveyPublic>, (StatusCode, String)> {
    let survey: Option<SurveyRow> =
        sqlx::query_as("SELECT id, enabled FROM surveys WHERE enabled = 1 LIMIT 1")
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let survey = match survey {
        None => return Ok(None),
        Some(s) => s,
    };

    let questions: Vec<QuestionRow> = sqlx::query_as(
        "SELECT id, prompt, kind, required, display_order FROM survey_questions WHERE survey_id = ? ORDER BY display_order",
    )
    .bind(&survey.id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut qout = Vec::with_capacity(questions.len());
    for q in questions {
        let choices: Option<Vec<SurveyChoicePublic>> = if q.kind == "choice" {
            let rows: Vec<ChoiceRow> = sqlx::query_as(
                "SELECT id, label, display_order FROM survey_choices WHERE question_id = ? ORDER BY display_order",
            )
            .bind(&q.id)
            .fetch_all(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            Some(
                rows.into_iter()
                    .map(|c| SurveyChoicePublic {
                        id: c.id,
                        label: c.label,
                        display_order: c.display_order,
                    })
                    .collect(),
            )
        } else {
            None
        };

        qout.push(SurveyQuestionPublic {
            id: q.id,
            prompt: q.prompt,
            kind: q.kind,
            required: q.required != 0,
            display_order: q.display_order,
            choices,
        });
    }

    Ok(Some(SurveyPublic {
        id: survey.id,
        questions: qout,
    }))
}

/// Load a survey with full admin data (role mappings).
async fn load_survey_admin(
    db: &sqlx::SqlitePool,
    survey_id: &str,
) -> Result<Option<SurveyAdmin>, (StatusCode, String)> {
    let survey: Option<SurveyRow> =
        sqlx::query_as("SELECT id, enabled FROM surveys WHERE id = ?")
            .bind(survey_id)
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let survey = match survey {
        None => return Ok(None),
        Some(s) => s,
    };

    let questions: Vec<QuestionRow> = sqlx::query_as(
        "SELECT id, prompt, kind, required, display_order FROM survey_questions WHERE survey_id = ? ORDER BY display_order",
    )
    .bind(&survey.id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut qout = Vec::with_capacity(questions.len());
    for q in questions {
        let choices: Option<Vec<SurveyChoiceAdmin>> = if q.kind == "choice" {
            let rows: Vec<ChoiceRow> = sqlx::query_as(
                "SELECT id, label, display_order FROM survey_choices WHERE question_id = ? ORDER BY display_order",
            )
            .bind(&q.id)
            .fetch_all(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            let mut cout = Vec::with_capacity(rows.len());
            for c in rows {
                let role_ids: Vec<String> = sqlx::query_scalar(
                    "SELECT role_id FROM survey_choice_roles WHERE choice_id = ?",
                )
                .bind(&c.id)
                .fetch_all(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                cout.push(SurveyChoiceAdmin {
                    id: c.id,
                    label: c.label,
                    display_order: c.display_order,
                    role_ids,
                });
            }
            Some(cout)
        } else {
            None
        };

        qout.push(SurveyQuestionAdmin {
            id: q.id,
            prompt: q.prompt,
            kind: q.kind,
            required: q.required != 0,
            display_order: q.display_order,
            choices,
        });
    }

    Ok(Some(SurveyAdmin {
        id: survey.id,
        enabled: survey.enabled != 0,
        questions: qout,
    }))
}

// ---------------------------------------------------------------------------
// Handlers — public
// ---------------------------------------------------------------------------

/// GET /survey/current
pub async fn get_current(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Option<SurveyPublic>>, (StatusCode, String)> {
    let survey = load_active_survey_public(&state.db).await?;
    Ok(Json(survey))
}

/// POST /survey/submit
pub async fn submit_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SubmitSurveyRequest>,
) -> Result<Json<SubmitSurveyResponse>, (StatusCode, String)> {
    // Load survey to validate required questions
    let survey = load_active_survey_public(&state.db)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "No active survey".to_string()))?;

    if survey.id != req.survey_id {
        return Err((StatusCode::BAD_REQUEST, "survey_id does not match active survey".to_string()));
    }

    // Validate required questions are answered
    for q in &survey.questions {
        if q.required {
            let answered = req.answers.iter().any(|a| {
                a.question_id == q.id && (a.choice_id.is_some() || a.text_answer.as_deref().map(|s| !s.is_empty()).unwrap_or(false))
            });
            if !answered {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("Required question '{}' not answered", q.id),
                ));
            }
        }
    }

    let now = crate::auth::handlers::unix_timestamp();
    let response_id = Uuid::new_v4().to_string();

    // Insert response (UNIQUE(pubkey, survey_id) — upsert not needed, return error on re-submit)
    let result = sqlx::query(
        "INSERT INTO survey_responses (id, pubkey, survey_id, submitted_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&response_id)
    .bind(&user.public_key)
    .bind(&req.survey_id)
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        let msg = e.to_string();
        if msg.contains("UNIQUE") {
            return Err((StatusCode::CONFLICT, "Survey already submitted".to_string()));
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")));
    }

    // Insert answers and collect applied roles
    let mut applied_roles: Vec<String> = Vec::new();
    let mut has_text = false;

    for a in &req.answers {
        sqlx::query(
            "INSERT INTO survey_answers (response_id, question_id, choice_id, text_answer) VALUES (?, ?, ?, ?)",
        )
        .bind(&response_id)
        .bind(&a.question_id)
        .bind(&a.choice_id)
        .bind(&a.text_answer)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if a.text_answer.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
            has_text = true;
        }

        // Apply role mappings for choice answers
        if let Some(choice_id) = &a.choice_id {
            let role_ids: Vec<String> = sqlx::query_scalar(
                "SELECT role_id FROM survey_choice_roles WHERE choice_id = ?",
            )
            .bind(choice_id)
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            for role_id in role_ids {
                sqlx::query(
                    "INSERT OR IGNORE INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, ?, ?)",
                )
                .bind(&user.public_key)
                .bind(&role_id)
                .bind(now)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                applied_roles.push(role_id);
            }
        }
    }

    // Set approval status based on whether there are text answers
    let next_state = if has_text {
        sqlx::query("UPDATE users SET approval_status = 'pending' WHERE public_key = ?")
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        "pending".to_string()
    } else {
        sqlx::query("UPDATE users SET approval_status = 'approved' WHERE public_key = ?")
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        "approved".to_string()
    };

    Ok(Json(SubmitSurveyResponse {
        next_state,
        applied_roles,
    }))
}

// ---------------------------------------------------------------------------
// Handlers — admin
// ---------------------------------------------------------------------------

/// GET /admin/survey
pub async fn admin_get_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Option<SurveyAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Find the active (or most-recently-updated) survey
    let survey_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM surveys ORDER BY enabled DESC, updated_at DESC LIMIT 1")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let survey = match survey_id {
        None => return Ok(Json(None)),
        Some(id) => load_survey_admin(&state.db, &id).await?,
    };

    Ok(Json(survey))
}

/// PUT /admin/survey
pub async fn admin_put_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SurveyAdmin>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let now = crate::auth::handlers::unix_timestamp();

    // Wrap in a transaction: delete old survey, insert new one.
    // SQLite doesn't have a clean BEGIN TRANSACTION in sqlx without a transaction object.
    // We delete by id and rely on CASCADE for child rows.
    // First, delete any existing survey with this id (or if id is new, just insert).
    sqlx::query("DELETE FROM surveys WHERE id = ?")
        .bind(&req.id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // If enabling this survey, disable all others first
    if req.enabled {
        sqlx::query("UPDATE surveys SET enabled = 0")
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    sqlx::query("INSERT INTO surveys (id, enabled, updated_at) VALUES (?, ?, ?)")
        .bind(&req.id)
        .bind(if req.enabled { 1i64 } else { 0i64 })
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for q in &req.questions {
        sqlx::query(
            "INSERT INTO survey_questions (id, survey_id, prompt, kind, required, display_order) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&q.id)
        .bind(&req.id)
        .bind(&q.prompt)
        .bind(&q.kind)
        .bind(if q.required { 1i64 } else { 0i64 })
        .bind(q.display_order)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if let Some(choices) = &q.choices {
            for c in choices {
                sqlx::query(
                    "INSERT INTO survey_choices (id, question_id, label, display_order) VALUES (?, ?, ?, ?)",
                )
                .bind(&c.id)
                .bind(&q.id)
                .bind(&c.label)
                .bind(c.display_order)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                for role_id in &c.role_ids {
                    sqlx::query(
                        "INSERT OR IGNORE INTO survey_choice_roles (choice_id, role_id) VALUES (?, ?)",
                    )
                    .bind(&c.id)
                    .bind(role_id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                }
            }
        }
    }

    Ok(StatusCode::OK)
}

/// GET /admin/survey/responses
pub async fn admin_list_responses(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ResponsesQuery>,
) -> Result<Json<Vec<SurveyResponseAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows: Vec<ResponseRow> = if q.status == "all" {
        sqlx::query_as(
            "SELECT sr.id, sr.pubkey, u.display_name, sr.submitted_at
             FROM survey_responses sr
             LEFT JOIN users u ON sr.pubkey = u.public_key
             ORDER BY sr.submitted_at DESC
             LIMIT ?",
        )
        .bind(q.limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    } else {
        // pending: users whose approval_status is 'pending' and have a survey response
        sqlx::query_as(
            "SELECT sr.id, sr.pubkey, u.display_name, sr.submitted_at
             FROM survey_responses sr
             LEFT JOIN users u ON sr.pubkey = u.public_key
             WHERE u.approval_status = 'pending'
             ORDER BY sr.submitted_at DESC
             LIMIT ?",
        )
        .bind(q.limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let answers = load_response_answers(&state.db, &r.id).await?;
        out.push(SurveyResponseAdmin {
            response_id: r.id,
            pubkey: r.pubkey,
            display_name: r.display_name,
            submitted_at: r.submitted_at,
            answers,
        });
    }

    Ok(Json(out))
}

/// GET /admin/survey/responses/:pubkey
pub async fn admin_get_response_for_pubkey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<Option<SurveyResponseAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let row: Option<ResponseRow> = sqlx::query_as(
        "SELECT sr.id, sr.pubkey, u.display_name, sr.submitted_at
         FROM survey_responses sr
         LEFT JOIN users u ON sr.pubkey = u.public_key
         WHERE sr.pubkey = ?
         ORDER BY sr.submitted_at DESC
         LIMIT 1",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        None => Ok(Json(None)),
        Some(r) => {
            let answers = load_response_answers(&state.db, &r.id).await?;
            Ok(Json(Some(SurveyResponseAdmin {
                response_id: r.id,
                pubkey: r.pubkey,
                display_name: r.display_name,
                submitted_at: r.submitted_at,
                answers,
            })))
        }
    }
}

async fn load_response_answers(
    db: &sqlx::SqlitePool,
    response_id: &str,
) -> Result<Vec<SurveyAnswerView>, (StatusCode, String)> {
    let rows: Vec<AnswerRow> = sqlx::query_as(
        "SELECT sa.question_id, sq.prompt, sc.label as choice_label, sa.text_answer
         FROM survey_answers sa
         LEFT JOIN survey_questions sq ON sa.question_id = sq.id
         LEFT JOIN survey_choices sc ON sa.choice_id = sc.id
         WHERE sa.response_id = ?",
    )
    .bind(response_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|r| SurveyAnswerView {
            question_id: r.question_id,
            prompt: r.prompt,
            choice_label: r.choice_label,
            text_answer: r.text_answer,
        })
        .collect())
}
