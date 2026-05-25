use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengePrompt {
    pub id: String,
    pub mode: String,
    pub prompt_svg: Option<String>,
    pub expires_at: i64,
}

#[derive(Serialize)]
pub struct ChallengeVerifyResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_challenge: Option<ChallengePrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts_remaining: Option<u32>,
}

#[derive(Deserialize)]
pub struct NewChallengeQuery {
    pub pubkey: String,
}

#[derive(Deserialize)]
pub struct VerifyChallengeRequest {
    pub id: String,
    pub pubkey: String,
    pub answer: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateChallengeSettingsRequest {
    pub challenge_mode: String,
    pub challenge_difficulty: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn read_setting(db: &sqlx::SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

async fn upsert_setting(
    db: &sqlx::SqlitePool,
    key: &str,
    value: &str,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = ?",
    )
    .bind(key)
    .bind(value)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

/// SHA-256 hex of a string (lowercase), for puzzle answer hashing.
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Generate a simple math puzzle SVG. Returns (svg_string, answer_string).
fn make_puzzle_svg(difficulty: &str) -> (String, String) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let (a, b) = if difficulty == "medium" {
        (rng.gen_range(10u32..=50), rng.gen_range(10u32..=50))
    } else {
        (rng.gen_range(1u32..=9), rng.gen_range(1u32..=9))
    };
    let answer = (a + b).to_string();

    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='80'>\
         <rect width='200' height='80' fill='#1a1a2e'/>\
         <line x1='0' y1='30' x2='200' y2='35' stroke='#333' stroke-width='1'/>\
         <line x1='10' y1='60' x2='190' y2='55' stroke='#2a2a4e' stroke-width='1'/>\
         <text x='20' y='52' font-size='26' fill='#e0e0ff' font-family='monospace' transform='rotate(-5,20,52)'>{a}</text>\
         <text x='72' y='55' font-size='26' fill='#e0e0ff' font-family='monospace'>+</text>\
         <text x='100' y='50' font-size='26' fill='#e0e0ff' font-family='monospace' transform='rotate(3,100,50)'>{b}</text>\
         <text x='145' y='53' font-size='26' fill='#c0c0ff' font-family='monospace'>=?</text>\
         </svg>",
        a = a,
        b = b,
    );
    (svg, answer)
}

/// Issue a challenge_token row and return the token string.
async fn issue_challenge_token(
    db: &sqlx::SqlitePool,
    pubkey: &str,
    now: i64,
) -> Result<(String, i64), (StatusCode, String)> {
    let token = {
        let mut bytes = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let expires_at = now + 300; // 5 minutes

    sqlx::query(
        "INSERT INTO challenge_tokens (token, pubkey, issued_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(pubkey)
    .bind(now)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((token, expires_at))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /challenge/new?pubkey=<hex>
pub async fn new_challenge(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NewChallengeQuery>,
) -> Result<Json<ChallengePrompt>, (StatusCode, String)> {
    let challenge_mode = read_setting(&state.db, "challenge_mode")
        .await
        .unwrap_or_else(|| "off".to_string());

    if challenge_mode == "off" {
        return Err((StatusCode::NOT_FOUND, "Challenges are disabled".to_string()));
    }

    let difficulty = read_setting(&state.db, "challenge_difficulty")
        .await
        .unwrap_or_else(|| "easy".to_string());

    let now = crate::auth::handlers::unix_timestamp();
    let expires_at = now + 300;
    let id = Uuid::new_v4().to_string();

    let (kind, expected_answer, prompt_svg) = match challenge_mode.as_str() {
        "click" => ("click".to_string(), None, None),
        "puzzle" => {
            let (svg, answer) = make_puzzle_svg(&difficulty);
            ("puzzle".to_string(), Some(sha256_hex(&answer)), Some(svg))
        }
        "both" => {
            // First step: click challenge. Client calls verify then gets puzzle.
            ("click".to_string(), None, None)
        }
        _ => ("click".to_string(), None, None),
    };

    sqlx::query(
        "INSERT INTO bot_challenges (id, pubkey, kind, expected_answer, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&q.pubkey)
    .bind(&kind)
    .bind(&expected_answer)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(ChallengePrompt {
        id,
        mode: challenge_mode,
        prompt_svg,
        expires_at,
    }))
}

/// POST /challenge/verify
pub async fn verify_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyChallengeRequest>,
) -> Result<Json<ChallengeVerifyResponse>, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // Look up challenge
    let row: Option<(String, String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT kind, pubkey, expected_answer, expires_at, consumed_at FROM bot_challenges WHERE id = ?",
    )
    .bind(&req.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (kind, db_pubkey, expected_answer, expires_at, consumed_at) =
        row.ok_or((StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    if consumed_at.is_some() {
        return Err((StatusCode::GONE, "Challenge already consumed".to_string()));
    }
    if now > expires_at {
        return Err((StatusCode::GONE, "Challenge expired".to_string()));
    }
    if db_pubkey != req.pubkey {
        return Err((StatusCode::FORBIDDEN, "Pubkey mismatch".to_string()));
    }

    let challenge_mode = read_setting(&state.db, "challenge_mode")
        .await
        .unwrap_or_else(|| "off".to_string());
    let difficulty = read_setting(&state.db, "challenge_difficulty")
        .await
        .unwrap_or_else(|| "easy".to_string());

    match kind.as_str() {
        "click" => {
            // Mark consumed
            sqlx::query("UPDATE bot_challenges SET consumed_at = ? WHERE id = ?")
                .bind(now)
                .bind(&req.id)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            if challenge_mode == "both" {
                // Generate puzzle step
                let puzzle_id = Uuid::new_v4().to_string();
                let puzzle_expires = now + 300;
                let (svg, answer) = make_puzzle_svg(&difficulty);
                let hashed = sha256_hex(&answer);

                sqlx::query(
                    "INSERT INTO bot_challenges (id, pubkey, kind, expected_answer, created_at, expires_at) VALUES (?, ?, 'puzzle', ?, ?, ?)",
                )
                .bind(&puzzle_id)
                .bind(&req.pubkey)
                .bind(&hashed)
                .bind(now)
                .bind(puzzle_expires)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                return Ok(Json(ChallengeVerifyResponse {
                    ok: true,
                    token: None,
                    expires_at: None,
                    next_challenge: Some(ChallengePrompt {
                        id: puzzle_id,
                        mode: "both".to_string(),
                        prompt_svg: Some(svg),
                        expires_at: puzzle_expires,
                    }),
                    attempts_remaining: None,
                }));
            }

            // click-only: issue token
            let (token, token_expires) =
                issue_challenge_token(&state.db, &req.pubkey, now).await?;
            Ok(Json(ChallengeVerifyResponse {
                ok: true,
                token: Some(token),
                expires_at: Some(token_expires),
                next_challenge: None,
                attempts_remaining: None,
            }))
        }
        "puzzle" => {
            let submitted = match &req.answer {
                None => {
                    return Ok(Json(ChallengeVerifyResponse {
                        ok: false,
                        token: None,
                        expires_at: None,
                        next_challenge: None,
                        attempts_remaining: Some(2),
                    }));
                }
                Some(a) => sha256_hex(a.trim()),
            };

            let expected = expected_answer
                .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Missing expected answer".to_string()))?;

            if submitted != expected {
                return Ok(Json(ChallengeVerifyResponse {
                    ok: false,
                    token: None,
                    expires_at: None,
                    next_challenge: None,
                    attempts_remaining: Some(2),
                }));
            }

            // Correct — mark consumed and issue token
            sqlx::query("UPDATE bot_challenges SET consumed_at = ? WHERE id = ?")
                .bind(now)
                .bind(&req.id)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            let (token, token_expires) =
                issue_challenge_token(&state.db, &req.pubkey, now).await?;
            Ok(Json(ChallengeVerifyResponse {
                ok: true,
                token: Some(token),
                expires_at: Some(token_expires),
                next_challenge: None,
                attempts_remaining: None,
            }))
        }
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "Unknown challenge kind".to_string())),
    }
}

/// PUT /hub/settings/challenge
pub async fn update_challenge_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateChallengeSettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let valid_modes = ["off", "click", "puzzle", "both"];
    if !valid_modes.contains(&req.challenge_mode.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid challenge_mode: {}", req.challenge_mode)));
    }
    let valid_difficulties = ["easy", "medium"];
    if !valid_difficulties.contains(&req.challenge_difficulty.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid challenge_difficulty: {}", req.challenge_difficulty)));
    }

    upsert_setting(&state.db, "challenge_mode", &req.challenge_mode).await?;
    upsert_setting(&state.db, "challenge_difficulty", &req.challenge_difficulty).await?;

    Ok(StatusCode::OK)
}
