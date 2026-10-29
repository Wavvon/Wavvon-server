//! The form engine behind both join forms (join-forms.md): the onboarding
//! survey a member answers after joining, here, and the application a joiner
//! fills before membership, in `application.rs`. One set of tables told apart
//! by `surveys.purpose`; the two forms differ in when they run and who reads
//! them, not in what a question can be.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, SURVEYS_MANAGE, SURVEYS_RESPONSES_READ};
use crate::state::AppState;

pub(crate) const ONBOARDING: &str = "onboarding";
pub(crate) const APPLICATION: &str = "application";

/// What a question can be. `consent` is a checkbox that, when required, must
/// be checked: an applicant who leaves it unchecked is stopped by the hub too,
/// not only by the client.
const KINDS: &[&str] = &["text", "choice", "multi", "consent"];

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

fn has_choices(kind: &str) -> bool {
    kind == "choice" || kind == "multi"
}

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
    pub help: Option<String>,
    pub multiline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_len: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_choices: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_choices: Option<i32>,
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
    #[serde(default)]
    pub role_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SurveyQuestionAdmin {
    pub id: String,
    pub prompt: String,
    pub kind: String,
    pub required: bool,
    pub display_order: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(default)]
    pub multiline: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_choices: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_choices: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// A `choice` answer.
    #[serde(default)]
    pub choice_id: Option<String>,
    /// A `multi` answer.
    #[serde(default)]
    pub choice_ids: Option<Vec<String>>,
    /// A `text` answer.
    #[serde(default)]
    pub text_answer: Option<String>,
    /// A `consent` answer.
    #[serde(default)]
    pub checked: Option<bool>,
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
    /// The chosen label; for a `multi` answer, the labels joined by ", ".
    pub choice_label: Option<String>,
    pub text_answer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
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
    /// The previous page's last `response_id`.
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
    enabled: bool,
}

#[derive(sqlx::FromRow)]
struct QuestionRow {
    id: String,
    prompt: String,
    kind: String,
    required: bool,
    display_order: i64,
    help: Option<String>,
    multiline: bool,
    max_len: Option<i32>,
    min_choices: Option<i32>,
    max_choices: Option<i32>,
}

#[derive(sqlx::FromRow)]
struct ChoiceRow {
    id: String,
    label: String,
    display_order: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct ResponseRow {
    id: String,
    pubkey: String,
    display_name: Option<String>,
    submitted_at: i64,
}

#[derive(sqlx::FromRow)]
struct AnswerRow {
    question_id: String,
    prompt: String,
    kind: Option<String>,
    choice_label: Option<String>,
    text_answer: Option<String>,
}

const QUESTION_COLUMNS: &str = "id, prompt, kind, required, display_order, help, multiline, \
     max_len, min_choices, max_choices";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn load_questions(
    db: &sqlx::PgPool,
    survey_id: &str,
) -> Result<Vec<QuestionRow>, (StatusCode, String)> {
    sqlx::query_as(&format!(
        "SELECT {QUESTION_COLUMNS} FROM survey_questions WHERE survey_id = $1 ORDER BY display_order"
    ))
    .bind(survey_id)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

async fn load_choices(
    db: &sqlx::PgPool,
    question_id: &str,
) -> Result<Vec<ChoiceRow>, (StatusCode, String)> {
    sqlx::query_as(
        "SELECT id, label, display_order FROM survey_choices WHERE question_id = $1 ORDER BY display_order",
    )
    .bind(question_id)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

/// The enabled form with this purpose, without role mappings.
pub(crate) async fn load_active_public(
    db: &sqlx::PgPool,
    purpose: &str,
) -> Result<Option<SurveyPublic>, (StatusCode, String)> {
    let survey: Option<SurveyRow> = sqlx::query_as(
        "SELECT id, enabled FROM surveys WHERE enabled = TRUE AND purpose = $1 LIMIT 1",
    )
    .bind(purpose)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    let Some(survey) = survey else {
        return Ok(None);
    };

    let mut qout = Vec::new();
    for q in load_questions(db, &survey.id).await? {
        let choices = if has_choices(&q.kind) {
            Some(
                load_choices(db, &q.id)
                    .await?
                    .into_iter()
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
            required: q.required,
            display_order: q.display_order,
            help: q.help,
            multiline: q.multiline,
            max_len: q.max_len,
            min_choices: q.min_choices,
            max_choices: q.max_choices,
            choices,
        });
    }

    Ok(Some(SurveyPublic {
        id: survey.id,
        questions: qout,
    }))
}

/// A form with full admin data (role mappings).
async fn load_survey_admin(
    db: &sqlx::PgPool,
    survey_id: &str,
) -> Result<Option<SurveyAdmin>, (StatusCode, String)> {
    let survey: Option<SurveyRow> = sqlx::query_as("SELECT id, enabled FROM surveys WHERE id = $1")
        .bind(survey_id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    let Some(survey) = survey else {
        return Ok(None);
    };

    let mut qout = Vec::new();
    for q in load_questions(db, &survey.id).await? {
        let choices = if has_choices(&q.kind) {
            let mut cout = Vec::new();
            for c in load_choices(db, &q.id).await? {
                let role_ids: Vec<String> = sqlx::query_scalar(
                    "SELECT role_id FROM survey_choice_roles WHERE choice_id = $1",
                )
                .bind(&c.id)
                .fetch_all(db)
                .await
                .map_err(db_err)?;
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
            required: q.required,
            display_order: q.display_order,
            help: q.help,
            multiline: q.multiline,
            max_len: q.max_len,
            min_choices: q.min_choices,
            max_choices: q.max_choices,
            choices,
        });
    }

    Ok(Some(SurveyAdmin {
        id: survey.id,
        enabled: survey.enabled,
        questions: qout,
    }))
}

fn unprocessable(msg: String) -> (StatusCode, String) {
    (StatusCode::UNPROCESSABLE_ENTITY, msg)
}

/// Check a submission against its form: every required question answered,
/// every answer of the shape its question asks for and within its limits,
/// every choice one the question offers. An unchecked required consent is
/// refused as `consent_refused:<question id>`, so a client can name it.
pub(crate) fn validate_answers(
    form: &SurveyPublic,
    answers: &[SurveyAnswerInput],
) -> Result<(), (StatusCode, String)> {
    for a in answers {
        if !form.questions.iter().any(|q| q.id == a.question_id) {
            return Err(unprocessable(format!(
                "Question '{}' is not on this form",
                a.question_id
            )));
        }
    }

    for q in &form.questions {
        let a = answers.iter().find(|a| a.question_id == q.id);
        let offered = |id: &str| {
            q.choices
                .as_ref()
                .is_some_and(|cs| cs.iter().any(|c| c.id == id))
        };
        let answered = match (q.kind.as_str(), a) {
            (_, None) => false,
            ("text", Some(a)) => {
                let text = a.text_answer.as_deref().unwrap_or("").trim();
                if let Some(max) = q.max_len {
                    if text.chars().count() > max.max(0) as usize {
                        return Err(unprocessable(format!(
                            "Answer to '{}' is longer than {max} characters",
                            q.id
                        )));
                    }
                }
                !text.is_empty()
            }
            ("choice", Some(a)) => match &a.choice_id {
                Some(id) if offered(id) => true,
                Some(_) => return Err(unprocessable(format!("Unknown choice for '{}'", q.id))),
                None => false,
            },
            ("multi", Some(a)) => {
                let ids = a.choice_ids.as_deref().unwrap_or(&[]);
                if ids.iter().any(|id| !offered(id)) {
                    return Err(unprocessable(format!("Unknown choice for '{}'", q.id)));
                }
                let n = ids.len() as i32;
                if q.min_choices.is_some_and(|min| n > 0 && n < min)
                    || q.max_choices.is_some_and(|max| n > max)
                {
                    return Err(unprocessable(format!(
                        "Wrong number of choices for '{}'",
                        q.id
                    )));
                }
                n > 0
            }
            ("consent", Some(a)) => a.checked == Some(true),
            _ => false,
        };
        if q.required && !answered {
            return Err(unprocessable(if q.kind == "consent" {
                format!("consent_refused:{}", q.id)
            } else {
                format!("Required question '{}' not answered", q.id)
            }));
        }
    }
    Ok(())
}

/// Store a validated submission's answers under a response row.
pub(crate) async fn store_answers(
    db: &sqlx::PgPool,
    response_id: &str,
    answers: &[SurveyAnswerInput],
) -> Result<(), (StatusCode, String)> {
    for a in answers {
        let text = match a.checked {
            Some(true) => Some("checked".to_string()),
            _ => a.text_answer.clone(),
        };
        sqlx::query(
            "INSERT INTO survey_answers (response_id, question_id, choice_id, text_answer) VALUES ($1, $2, $3, $4)",
        )
        .bind(response_id)
        .bind(&a.question_id)
        .bind(&a.choice_id)
        .bind(&text)
        .execute(db)
        .await
        .map_err(db_err)?;
        for choice_id in a.choice_ids.iter().flatten() {
            sqlx::query(
                "INSERT INTO survey_answer_choices (response_id, question_id, choice_id) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
            )
            .bind(response_id)
            .bind(&a.question_id)
            .bind(choice_id)
            .execute(db)
            .await
            .map_err(db_err)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers — onboarding survey
// ---------------------------------------------------------------------------

/// GET /survey/current
pub async fn get_current(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Option<SurveyPublic>>, (StatusCode, String)> {
    Ok(Json(load_active_public(&state.db, ONBOARDING).await?))
}

/// POST /survey/submit
pub async fn submit_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SubmitSurveyRequest>,
) -> Result<Json<SubmitSurveyResponse>, (StatusCode, String)> {
    let survey = load_active_public(&state.db, ONBOARDING)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "No active survey".to_string()))?;
    if survey.id != req.survey_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "survey_id does not match active survey".to_string(),
        ));
    }
    validate_answers(&survey, &req.answers)?;

    let now = crate::auth::handlers::unix_timestamp();
    let response_id = Uuid::new_v4().to_string();

    // UNIQUE(pubkey, survey_id): a second submission is refused, not merged.
    let result = sqlx::query(
        "INSERT INTO survey_responses (id, pubkey, survey_id, submitted_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&response_id)
    .bind(&user.public_key)
    .bind(&req.survey_id)
    .bind(now)
    .execute(&state.db)
    .await;
    if let Err(e) = result {
        if matches!(&e, sqlx::Error::Database(dbe) if dbe.code().is_some_and(|c| c == "23505")) {
            return Err((StatusCode::CONFLICT, "Survey already submitted".to_string()));
        }
        return Err(db_err(e));
    }

    store_answers(&state.db, &response_id, &req.answers).await?;

    // Free-text always routes to manual review (lobby-survey.md Feature 3:
    // "the hub cannot mechanically decide if a free-text answer earns
    // roles"). Mapped roles are applied only when no answered question is
    // free-text; otherwise admins assign roles when they review.
    let has_text = req.answers.iter().any(|a| {
        a.text_answer
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    });

    let mut applied_roles: Vec<String> = Vec::new();
    if !has_text {
        let chosen = req
            .answers
            .iter()
            .flat_map(|a| a.choice_id.iter().chain(a.choice_ids.iter().flatten()))
            .cloned()
            .collect::<Vec<String>>();
        for choice_id in &chosen {
            let role_ids: Vec<String> =
                sqlx::query_scalar("SELECT role_id FROM survey_choice_roles WHERE choice_id = $1")
                    .bind(choice_id)
                    .fetch_all(&state.db)
                    .await
                    .map_err(db_err)?;
            for role_id in role_ids {
                sqlx::query(
                    "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, $2, $3)
                     ON CONFLICT (user_public_key, role_id) DO NOTHING",
                )
                .bind(&user.public_key)
                .bind(&role_id)
                .bind(now)
                .execute(&state.db)
                .await
                .map_err(db_err)?;
                applied_roles.push(role_id);
            }
        }
    }

    let next_state = if has_text {
        sqlx::query("UPDATE users SET approval_status = 'pending' WHERE public_key = $1")
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(db_err)?;
        "pending".to_string()
    } else {
        sqlx::query(
            "UPDATE users SET approval_status = 'approved' WHERE public_key = $1
             AND NOT EXISTS (SELECT 1 FROM admission_flags WHERE public_key = $1)",
        )
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
        "approved".to_string()
    };

    Ok(Json(SubmitSurveyResponse {
        next_state,
        applied_roles,
    }))
}

// ---------------------------------------------------------------------------
// Handlers — admin, shared by both forms
// ---------------------------------------------------------------------------

/// The enabled form with this purpose, or the most recently edited one.
pub(crate) async fn admin_get_form(
    db: &sqlx::PgPool,
    purpose: &str,
) -> Result<Option<SurveyAdmin>, (StatusCode, String)> {
    let survey_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM surveys WHERE purpose = $1 ORDER BY enabled DESC, updated_at DESC LIMIT 1",
    )
    .bind(purpose)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    match survey_id {
        None => Ok(None),
        Some(id) => load_survey_admin(db, &id).await,
    }
}

/// GET /admin/survey
pub async fn admin_get_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Option<SurveyAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(SURVEYS_MANAGE)?;
    Ok(Json(admin_get_form(&state.db, ONBOARDING).await?))
}

/// Validates every role a choice can grant: it must exist, and it must not
/// carry a permission the survey's author does not hold themselves.
///
/// A survey is a **self-service onboarding gate** — whoever answers it grants
/// themselves the mapped roles with nobody in the loop — so it is a role-grant
/// path like `create_role`, `assign_role` and a role-granting invite, and it
/// takes the same escalation ceiling (permissions.md §1.6). It used to refuse
/// only roles holding `admin`; with the wildcard gone that check had nothing
/// left to look for, and the ceiling is what it was reaching for all along.
async fn validate_role_mappings(
    db: &sqlx::PgPool,
    perms: &permissions::UserPermissions,
    req: &SurveyAdmin,
) -> Result<(), (StatusCode, String)> {
    let mut role_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for q in &req.questions {
        if let Some(choices) = &q.choices {
            for c in choices {
                for role_id in &c.role_ids {
                    role_ids.insert(role_id.as_str());
                }
            }
        }
    }

    for role_id in role_ids {
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(db)
            .await
            .map_err(db_err)?;
        if exists.is_none() {
            return Err(unprocessable(format!("Role '{role_id}' does not exist")));
        }

        let carried: Vec<String> =
            sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_id = $1")
                .bind(role_id)
                .fetch_all(db)
                .await
                .map_err(db_err)?;
        if let Some(p) = perms.first_not_held(carried.iter().map(String::as_str)) {
            return Err(unprocessable(format!(
                "Role '{role_id}' carries '{p}', which you do not hold — a survey cannot grant it"
            )));
        }
        if role_id == permissions::BUILTIN_OWNER_ROLE_ID {
            return Err(unprocessable(
                "A survey cannot hand out ownership".to_string(),
            ));
        }
    }

    Ok(())
}

/// Replace the form with this purpose. An application cannot map choices to
/// roles: they would go to someone nobody has approved yet.
pub(crate) async fn admin_put_form(
    state: &AppState,
    perms: &permissions::UserPermissions,
    purpose: &str,
    req: &SurveyAdmin,
) -> Result<(), (StatusCode, String)> {
    for q in &req.questions {
        if !KINDS.contains(&q.kind.as_str()) {
            return Err(unprocessable(format!("Unknown question kind '{}'", q.kind)));
        }
        if has_choices(&q.kind) && q.choices.as_ref().is_none_or(|c| c.is_empty()) {
            return Err(unprocessable(format!(
                "Question '{}' offers no choices",
                q.id
            )));
        }
    }
    if purpose == APPLICATION {
        let maps_roles = req
            .questions
            .iter()
            .flat_map(|q| q.choices.iter().flatten())
            .any(|c| !c.role_ids.is_empty());
        if maps_roles {
            return Err(unprocessable(
                "An application cannot grant roles: nobody has approved the applicant yet"
                    .to_string(),
            ));
        }
    } else {
        validate_role_mappings(&state.db, perms, req).await?;
    }

    let now = crate::auth::handlers::unix_timestamp();
    let mut tx = state.db.begin().await.map_err(db_err)?;

    // Child rows go with the survey row (ON DELETE CASCADE).
    sqlx::query("DELETE FROM surveys WHERE id = $1")
        .bind(&req.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if req.enabled {
        sqlx::query("UPDATE surveys SET enabled = FALSE WHERE purpose = $1")
            .bind(purpose)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
    }
    sqlx::query("INSERT INTO surveys (id, enabled, updated_at, purpose) VALUES ($1, $2, $3, $4)")
        .bind(&req.id)
        .bind(req.enabled)
        .bind(now)
        .bind(purpose)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    for q in &req.questions {
        sqlx::query(
            "INSERT INTO survey_questions (id, survey_id, prompt, kind, required, display_order,
                 help, multiline, max_len, min_choices, max_choices)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&q.id)
        .bind(&req.id)
        .bind(&q.prompt)
        .bind(&q.kind)
        .bind(q.required)
        .bind(q.display_order)
        .bind(&q.help)
        .bind(q.multiline)
        .bind(q.max_len)
        .bind(q.min_choices)
        .bind(q.max_choices)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        for c in q.choices.iter().flatten() {
            sqlx::query(
                "INSERT INTO survey_choices (id, question_id, label, display_order) VALUES ($1, $2, $3, $4)",
            )
            .bind(&c.id)
            .bind(&q.id)
            .bind(&c.label)
            .bind(c.display_order)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            for role_id in &c.role_ids {
                sqlx::query(
                    "INSERT INTO survey_choice_roles (choice_id, role_id) VALUES ($1, $2)
                     ON CONFLICT (choice_id, role_id) DO NOTHING",
                )
                .bind(&c.id)
                .bind(role_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
        }
    }

    tx.commit().await.map_err(db_err)
}

/// PUT /admin/survey
pub async fn admin_put_survey(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SurveyAdmin>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(SURVEYS_MANAGE)?;
    admin_put_form(&state, &perms, ONBOARDING, &req).await?;
    Ok(StatusCode::OK)
}

/// GET /admin/survey/responses
pub async fn admin_list_responses(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ResponsesQuery>,
) -> Result<Json<Vec<SurveyResponseAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(SURVEYS_RESPONSES_READ)?;

    let limit = q.limit.clamp(1, crate::routes::paging::MAX_LIMIT);
    // "pending" narrows to members still waiting on approval. Application
    // answers are never listed here: they belong to the approval queue.
    let rows: Vec<ResponseRow> = sqlx::query_as(
        "SELECT sr.id, sr.pubkey, u.display_name, sr.submitted_at
         FROM survey_responses sr
         JOIN surveys s ON s.id = sr.survey_id AND s.purpose = 'onboarding'
         LEFT JOIN users u ON sr.pubkey = u.public_key
         WHERE ($3 OR u.approval_status = 'pending')
           AND ($2::text IS NULL OR (sr.submitted_at, sr.id) <
                ((SELECT submitted_at FROM survey_responses WHERE id = $2), $2))
         ORDER BY sr.submitted_at DESC, sr.id DESC
         LIMIT $1",
    )
    .bind(limit)
    .bind(&q.cursor)
    .bind(q.status == "all")
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(response_admin(&state.db, r).await?);
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
    perms.require(SURVEYS_RESPONSES_READ)?;
    Ok(Json(latest_response(&state.db, &pubkey, ONBOARDING).await?))
}

/// The latest response of one identity to the form with this purpose.
pub(crate) async fn latest_response(
    db: &sqlx::PgPool,
    pubkey: &str,
    purpose: &str,
) -> Result<Option<SurveyResponseAdmin>, (StatusCode, String)> {
    let row: Option<ResponseRow> = sqlx::query_as(
        "SELECT sr.id, sr.pubkey, u.display_name, sr.submitted_at
         FROM survey_responses sr
         JOIN surveys s ON s.id = sr.survey_id AND s.purpose = $2
         LEFT JOIN users u ON sr.pubkey = u.public_key
         WHERE sr.pubkey = $1
         ORDER BY sr.submitted_at DESC
         LIMIT 1",
    )
    .bind(pubkey)
    .bind(purpose)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(response_admin(db, r).await?)),
    }
}

async fn response_admin(
    db: &sqlx::PgPool,
    r: ResponseRow,
) -> Result<SurveyResponseAdmin, (StatusCode, String)> {
    let answers = load_response_answers(db, &r.id).await?;
    Ok(SurveyResponseAdmin {
        response_id: r.id,
        pubkey: r.pubkey,
        display_name: r.display_name,
        submitted_at: r.submitted_at,
        answers,
    })
}

async fn load_response_answers(
    db: &sqlx::PgPool,
    response_id: &str,
) -> Result<Vec<SurveyAnswerView>, (StatusCode, String)> {
    let rows: Vec<AnswerRow> = sqlx::query_as(
        "SELECT sa.question_id, sq.prompt, sq.kind,
                COALESCE(sc.label, (
                    SELECT string_agg(c.label, ', ' ORDER BY c.display_order)
                    FROM survey_answer_choices ac JOIN survey_choices c ON c.id = ac.choice_id
                    WHERE ac.response_id = sa.response_id AND ac.question_id = sa.question_id
                )) AS choice_label,
                sa.text_answer
         FROM survey_answers sa
         LEFT JOIN survey_questions sq ON sa.question_id = sq.id
         LEFT JOIN survey_choices sc ON sa.choice_id = sc.id
         WHERE sa.response_id = $1
         ORDER BY sq.display_order",
    )
    .bind(response_id)
    .fetch_all(db)
    .await
    .map_err(db_err)?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let consent = r.kind.as_deref() == Some("consent");
            SurveyAnswerView {
                question_id: r.question_id,
                prompt: r.prompt,
                choice_label: r.choice_label,
                checked: consent.then(|| r.text_answer.as_deref() == Some("checked")),
                text_answer: if consent { None } else { r.text_answer },
            }
        })
        .collect())
}
