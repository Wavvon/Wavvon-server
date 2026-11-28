//! The badge catalogue (achievement-badges.md): badges defined once, earned
//! by hand, by a rule over the member's running totals, or from a program.
//! Every award is still a signed badge cert (`routes::certs`), so a badge
//! travels in the member's portfolio and is revoked the way certs are.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::handlers::unix_timestamp;
use crate::auth::middleware::AuthUser;
use crate::permissions::{self, BADGES_MANAGE, BADGES_PROGRAMS};
use crate::state::AppState;

type ApiResult<T> = Result<T, (StatusCode, String)>;

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

/// The rules the hub can check by itself. Thresholds are seconds for the
/// durations and counts for the rest.
const RULES: &[&str] = &[
    "manual",
    "member_age",
    "online",
    "messages",
    "active_days",
    "voice",
    "role_held",
];

/// A program may define this many badges; a runaway bot stops here.
const PROGRAM_BADGE_CAP: i64 = 50;
/// And grant or revoke this many times a minute.
const PROGRAM_BADGE_CALLS_PER_MINUTE: u32 = 60;

/// Every grant mints and signs a certificate and revokes the one before, so
/// the budget counts calls, not award rows (#473).
fn program_over_budget(state: &AppState, program: &str) -> ApiResult<()> {
    let window = std::time::Duration::from_secs(60);
    let now = std::time::Instant::now();
    let mut map = state
        .rate_limiters
        .program_badge_calls
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if map.len() >= 2_000 {
        map.retain(|_, (_, t)| now.duration_since(*t) <= window);
    }
    let entry = map.entry(program.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > window {
        *entry = (0, now);
    }
    entry.0 += 1;
    if entry.0 > PROGRAM_BADGE_CALLS_PER_MINUTE {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many badge grants this minute".to_string(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct BadgeLevel {
    pub level: i32,
    pub name: String,
    #[serde(default)]
    pub threshold: i64,
}

#[derive(Serialize, Clone)]
pub struct BadgeDef {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub rule: String,
    pub role_id: Option<String>,
    pub keep_while: bool,
    /// The program that owns this badge, when a program made it.
    pub program_pubkey: Option<String>,
    /// How to earn it, in the program's own words; never checked by the hub.
    pub declared_rule: Option<String>,
    pub hidden: bool,
    pub levels: Vec<BadgeLevel>,
    /// Members holding each level, by level number.
    pub holders: HashMap<i32, i64>,
}

#[derive(sqlx::FromRow)]
struct DefRow {
    id: String,
    name: String,
    icon: Option<String>,
    description: Option<String>,
    rule: String,
    role_id: Option<String>,
    keep_while: bool,
    program_pubkey: Option<String>,
    declared_rule: Option<String>,
    hidden: bool,
}

async fn load_def(db: &sqlx::PgPool, id: &str) -> ApiResult<DefRow> {
    sqlx::query_as::<_, DefRow>(
        "SELECT id, name, icon, description, rule, role_id, keep_while, program_pubkey, declared_rule, hidden
         FROM badge_defs WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "No such badge".to_string()))
}

async fn levels_of(db: &sqlx::PgPool, id: &str) -> ApiResult<Vec<BadgeLevel>> {
    sqlx::query_as::<_, BadgeLevel>(
        "SELECT level, name, threshold FROM badge_levels WHERE badge_id = $1 ORDER BY level",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

async fn full_def(db: &sqlx::PgPool, row: DefRow) -> ApiResult<BadgeDef> {
    let levels = levels_of(db, &row.id).await?;
    let holders: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT level, COUNT(*) FROM badge_awards WHERE badge_id = $1 GROUP BY level",
    )
    .bind(&row.id)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(BadgeDef {
        id: row.id,
        name: row.name,
        icon: row.icon,
        description: row.description,
        rule: row.rule,
        role_id: row.role_id,
        keep_while: row.keep_while,
        program_pubkey: row.program_pubkey,
        declared_rule: row.declared_rule,
        hidden: row.hidden,
        levels,
        holders: holders.into_iter().collect(),
    })
}

// ---------------------------------------------------------------------------
// Running totals
// ---------------------------------------------------------------------------

/// A message a member sent: one more message, and one more active day if it
/// is the first today.
pub async fn count_message(db: &sqlx::PgPool, pubkey: &str, now: i64) {
    let day = now / 86400;
    let _ = sqlx::query(
        "INSERT INTO member_stats (public_key, messages, active_days, last_active_day)
         VALUES ($1, 1, 1, $2)
         ON CONFLICT (public_key) DO UPDATE SET
            messages = member_stats.messages + 1,
            active_days = member_stats.active_days
                + CASE WHEN member_stats.last_active_day IS DISTINCT FROM $2 THEN 1 ELSE 0 END,
            last_active_day = $2",
    )
    .bind(pubkey)
    .bind(day)
    .execute(db)
    .await;
}

/// The first socket of a member opened: time online starts. The socket
/// refcount decides first and last, so two tabs count once.
pub async fn went_online(db: &sqlx::PgPool, pubkey: &str, now: i64) {
    let _ = sqlx::query(
        "INSERT INTO member_stats (public_key, online_since) VALUES ($1, $2)
         ON CONFLICT (public_key) DO UPDATE SET online_since = $2",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await;
}

/// The last socket closed: the time since it started is added.
pub async fn went_offline(db: &sqlx::PgPool, pubkey: &str, now: i64) {
    let _ = sqlx::query(
        "UPDATE member_stats SET online_seconds = online_seconds + GREATEST(0, $2 - online_since), online_since = NULL
         WHERE public_key = $1 AND online_since IS NOT NULL",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await;
}

pub async fn voice_joined(db: &sqlx::PgPool, pubkey: &str, now: i64) {
    let _ = sqlx::query(
        "INSERT INTO member_stats (public_key, voice_since) VALUES ($1, $2)
         ON CONFLICT (public_key) DO UPDATE SET voice_since = COALESCE(member_stats.voice_since, $2)",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await;
}

pub async fn voice_left(db: &sqlx::PgPool, pubkey: &str, now: i64) {
    let _ = sqlx::query(
        "UPDATE member_stats SET voice_seconds = voice_seconds + GREATEST(0, $2 - voice_since), voice_since = NULL
         WHERE public_key = $1 AND voice_since IS NOT NULL",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Each member's measure for a rule: members in good standing only.
async fn measures(
    db: &sqlx::PgPool,
    rule: &str,
    role_id: Option<&str>,
    now: i64,
) -> ApiResult<Vec<(String, i64)>> {
    let base = "FROM users u LEFT JOIN member_stats s ON s.public_key = u.public_key
                WHERE u.is_member AND u.approval_status = 'approved'
                  AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key
                                  AND (b.expires_at IS NULL OR b.expires_at > $1))";
    let q = match rule {
        "member_age" => format!("SELECT u.public_key, $1 - u.first_seen_at {base}"),
        "online" => format!(
            "SELECT u.public_key, COALESCE(s.online_seconds, 0)
                + CASE WHEN s.online_since IS NULL THEN 0 ELSE GREATEST(0, $1 - s.online_since) END {base}"
        ),
        "messages" => format!("SELECT u.public_key, COALESCE(s.messages, 0) {base}"),
        "active_days" => format!("SELECT u.public_key, COALESCE(s.active_days, 0) {base}"),
        "voice" => format!(
            "SELECT u.public_key, COALESCE(s.voice_seconds, 0)
                + CASE WHEN s.voice_since IS NULL THEN 0 ELSE GREATEST(0, $1 - s.voice_since) END {base}"
        ),
        "role_held" => "SELECT u.public_key, $1 - r.assigned_at
             FROM users u JOIN user_roles r ON r.user_public_key = u.public_key AND r.role_id = $2
             WHERE u.is_member AND u.approval_status = 'approved'
               AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key
                               AND (b.expires_at IS NULL OR b.expires_at > $1))"
            .to_string(),
        _ => return Ok(Vec::new()),
    };
    sqlx::query_as::<_, (String, i64)>(&q)
        .bind(now)
        .bind(role_id.unwrap_or(""))
        .fetch_all(db)
        .await
        .map_err(db_err)
}

/// The highest level whose threshold `value` reaches.
fn level_for(levels: &[BadgeLevel], value: i64) -> Option<&BadgeLevel> {
    levels
        .iter()
        .filter(|l| value >= l.threshold)
        .max_by_key(|l| l.level)
}

/// How many members would hold each level right now: the retroactive preview.
async fn preview_counts(
    db: &sqlx::PgPool,
    rule: &str,
    role_id: Option<&str>,
    levels: &[BadgeLevel],
) -> ApiResult<HashMap<i32, i64>> {
    let mut counts = HashMap::new();
    for (_, value) in measures(db, rule, role_id, unix_timestamp()).await? {
        if let Some(l) = level_for(levels, value) {
            *counts.entry(l.level).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// Gives `pubkey` level `level` of the badge, replacing any previous award:
/// the old cert is revoked, so a portfolio shows one current level.
async fn award(state: &AppState, def: &DefRow, level: &BadgeLevel, pubkey: &str) -> ApiResult<()> {
    let label = if level.name.trim().is_empty() {
        def.name.clone()
    } else {
        level.name.clone()
    };
    let (cert_id, _) = crate::routes::certs::issue_badge_cert(
        state,
        pubkey,
        &label,
        def.description.as_deref(),
        def.icon.as_deref(),
    )
    .await?;
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT cert_id FROM badge_awards WHERE badge_id = $1 AND subject_pubkey = $2",
    )
    .bind(&def.id)
    .bind(pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    if let Some(old) = previous {
        crate::routes::certs::revoke_issuance_by_id(&state.db, &old)
            .await
            .map_err(db_err)?;
    }
    sqlx::query(
        "INSERT INTO badge_awards (badge_id, subject_pubkey, level, cert_id, awarded_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (badge_id, subject_pubkey) DO UPDATE SET
            level = excluded.level, cert_id = excluded.cert_id, awarded_at = excluded.awarded_at",
    )
    .bind(&def.id)
    .bind(pubkey)
    .bind(level.level)
    .bind(&cert_id)
    .bind(unix_timestamp())
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn unaward(state: &AppState, badge_id: &str, pubkey: &str) -> ApiResult<()> {
    let cert: Option<String> = sqlx::query_scalar(
        "DELETE FROM badge_awards WHERE badge_id = $1 AND subject_pubkey = $2 RETURNING cert_id",
    )
    .bind(badge_id)
    .bind(pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    if let Some(c) = cert {
        crate::routes::certs::revoke_issuance_by_id(&state.db, &c)
            .await
            .map_err(db_err)?;
    }
    Ok(())
}

/// One rule badge brought up to date: new holders, level changes, and, for a
/// conditional badge, holders who no longer qualify. An award whose cert
/// expired or was revoked (a ban) is issued again if it still applies.
async fn evaluate(state: &AppState, def: &DefRow) -> ApiResult<()> {
    let levels = levels_of(&state.db, &def.id).await?;
    if levels.is_empty() {
        return Ok(());
    }
    let now = unix_timestamp();
    let current: HashMap<String, (i32, bool)> = sqlx::query_as::<_, (String, i32, bool)>(
        "SELECT a.subject_pubkey, a.level,
                COALESCE(c.revoked_at IS NULL AND c.expires_at > $2, FALSE)
         FROM badge_awards a LEFT JOIN cert_issuances c ON c.id = a.cert_id
         WHERE a.badge_id = $1",
    )
    .bind(&def.id)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|(pk, level, live)| (pk, (level, live)))
    .collect();

    let mut qualified = std::collections::HashSet::new();
    for (pk, value) in measures(&state.db, &def.rule, def.role_id.as_deref(), now).await? {
        let Some(target) = level_for(&levels, value) else {
            continue;
        };
        qualified.insert(pk.clone());
        let held = current.get(&pk);
        let next = match held {
            None => Some(target),
            Some(&(lvl, live)) if lvl < target.level || !live => Some(target),
            // Lower than held: a conditional badge follows the measure down,
            // a kept one keeps its best.
            Some(&(lvl, _)) if lvl > target.level && def.keep_while => Some(target),
            _ => None,
        };
        if let Some(l) = next {
            if let Err((code, msg)) = award(state, def, l, &pk).await {
                tracing::debug!(
                    "badge {} for {}: HTTP {code} {msg}",
                    def.id,
                    &pk[..16.min(pk.len())]
                );
            }
        }
    }
    if def.keep_while {
        for pk in current.keys().filter(|pk| !qualified.contains(*pk)) {
            unaward(state, &def.id, pk).await?;
        }
    }
    Ok(())
}

/// Every hub rule badge, on the certificate worker's tick.
pub async fn evaluate_all(state: &AppState) -> anyhow::Result<()> {
    let defs = sqlx::query_as::<_, DefRow>(
        "SELECT id, name, icon, description, rule, role_id, keep_while, program_pubkey, declared_rule, hidden
         FROM badge_defs WHERE rule <> 'manual' AND program_pubkey IS NULL",
    )
    .fetch_all(&state.db)
    .await?;
    for def in defs {
        if let Err((code, msg)) = evaluate(state, &def).await {
            tracing::warn!("badge rule {} failed: HTTP {code} {msg}", def.id);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Admin: the catalogue
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DefRequest {
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub rule: String,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub keep_while: bool,
    pub levels: Vec<BadgeLevel>,
}

fn validate(req: &DefRequest) -> ApiResult<()> {
    let bad = |m: &str| Err((StatusCode::BAD_REQUEST, m.to_string()));
    if req.name.trim().is_empty() || req.name.len() > 64 {
        return bad("name must be 1–64 chars");
    }
    if !RULES.contains(&req.rule.as_str()) {
        return bad("unknown rule");
    }
    if req.rule == "role_held" && req.role_id.is_none() {
        return bad("role_held needs a role_id");
    }
    if req.levels.is_empty() || req.levels.len() > 10 {
        return bad("a badge has 1 to 10 levels");
    }
    if req
        .levels
        .iter()
        .any(|l| l.name.len() > 64 || l.threshold < 0)
    {
        return bad("a level has a name up to 64 chars and a threshold of 0 or more");
    }
    Ok(())
}

/// Levels numbered in threshold order, whatever order they came in.
fn numbered(levels: &[BadgeLevel]) -> Vec<BadgeLevel> {
    let mut v = levels.to_vec();
    v.sort_by_key(|l| l.threshold);
    v.iter()
        .enumerate()
        .map(|(i, l)| BadgeLevel {
            level: i as i32 + 1,
            name: l.name.trim().to_string(),
            threshold: l.threshold,
        })
        .collect()
}

async fn insert_def(
    state: &AppState,
    req: &DefRequest,
    program: Option<&str>,
    declared: Option<&str>,
) -> ApiResult<String> {
    let id = Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await.map_err(db_err)?;
    sqlx::query(
        "INSERT INTO badge_defs (id, name, icon, description, rule, role_id, keep_while, program_pubkey, declared_rule, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&id)
    .bind(req.name.trim())
    .bind(&req.icon)
    .bind(&req.description)
    .bind(&req.rule)
    .bind(&req.role_id)
    .bind(req.keep_while)
    .bind(program)
    .bind(declared)
    .bind(unix_timestamp())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    for l in numbered(&req.levels) {
        sqlx::query(
            "INSERT INTO badge_levels (badge_id, level, name, threshold) VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(l.level)
        .bind(&l.name)
        .bind(l.threshold)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(id)
}

/// GET /badges/defs: the catalogue as members see it (hidden ones left out
/// unless the caller manages badges).
pub async fn list_defs(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> ApiResult<Json<Vec<BadgeDef>>> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    let manager = perms.has(BADGES_MANAGE);
    let rows = sqlx::query_as::<_, DefRow>(
        "SELECT id, name, icon, description, rule, role_id, keep_while, program_pubkey, declared_rule, hidden
         FROM badge_defs WHERE $1 OR NOT hidden ORDER BY created_at, id",
    )
    .bind(manager)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(full_def(&state.db, r).await?);
    }
    Ok(Json(out))
}

/// POST /admin/badge-defs/preview: how many members a rule badge would reach.
pub async fn preview_def(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<DefRequest>,
) -> ApiResult<Json<HashMap<i32, i64>>> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    validate(&req)?;
    let levels = numbered(&req.levels);
    Ok(Json(
        preview_counts(&state.db, &req.rule, req.role_id.as_deref(), &levels).await?,
    ))
}

/// POST /admin/badge-defs: a hub badge, by hand or by rule. A rule badge is
/// retroactive: whoever already qualifies receives it now.
pub async fn create_def(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<DefRequest>,
) -> ApiResult<(StatusCode, Json<BadgeDef>)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    validate(&req)?;
    let id = insert_def(&state, &req, None, None).await?;
    let def = load_def(&state.db, &id).await?;
    if def.rule != "manual" {
        evaluate(&state, &def).await?;
    }
    let def = load_def(&state.db, &id).await?;
    Ok((StatusCode::CREATED, Json(full_def(&state.db, def).await?)))
}

#[derive(Deserialize)]
pub struct PatchDef {
    pub hidden: Option<bool>,
}

/// PATCH /admin/badge-defs/:id: hide or show a badge, a program's included.
pub async fn patch_def(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<PatchDef>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    load_def(&state.db, &id).await?;
    if let Some(h) = req.hidden {
        sqlx::query("UPDATE badge_defs SET hidden = $1 WHERE id = $2")
            .bind(h)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(db_err)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_def_and_revoke(state: &AppState, id: &str) -> ApiResult<()> {
    let certs: Vec<String> =
        sqlx::query_scalar("SELECT cert_id FROM badge_awards WHERE badge_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await
            .map_err(db_err)?;
    for c in certs {
        crate::routes::certs::revoke_issuance_by_id(&state.db, &c)
            .await
            .map_err(db_err)?;
    }
    sqlx::query("DELETE FROM badge_defs WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// DELETE /admin/badge-defs/:id: removes the badge and revokes every award.
pub async fn delete_def(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    load_def(&state.db, &id).await?;
    delete_def_and_revoke(&state, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Award {
    pub subject_pubkey: String,
    pub level: i32,
    pub awarded_at: i64,
}

/// GET /admin/badge-defs/:id/awards
pub async fn list_awards(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Award>>> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    let rows = sqlx::query_as::<_, Award>(
        "SELECT subject_pubkey, level, awarded_at FROM badge_awards WHERE badge_id = $1 ORDER BY awarded_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct GrantRequest {
    pub subjects: Vec<String>,
    #[serde(default)]
    pub level: Option<i32>,
}

/// POST /admin/badge-defs/:id/grant: a hand badge to several members at once.
pub async fn grant_manual(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<GrantRequest>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    let def = load_def(&state.db, &id).await?;
    if def.rule != "manual" || def.program_pubkey.is_some() {
        return Err((
            StatusCode::CONFLICT,
            "Only a hand badge is granted by hand".to_string(),
        ));
    }
    let levels = levels_of(&state.db, &id).await?;
    let level = pick_level(&levels, req.level)?;
    for pk in &req.subjects {
        award(&state, &def, level, pk).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn pick_level(levels: &[BadgeLevel], wanted: Option<i32>) -> ApiResult<&BadgeLevel> {
    match wanted {
        Some(n) => levels.iter().find(|l| l.level == n),
        None => levels.first(),
    }
    .ok_or((StatusCode::BAD_REQUEST, "No such level".to_string()))
}

/// DELETE /admin/badge-defs/:id/awards/:pubkey
pub async fn revoke_manual(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((id, pubkey)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_MANAGE)?;
    unaward(&state, &id, &pubkey).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Programs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ProgramDefRequest {
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// How to earn it, in the program's words.
    #[serde(default)]
    pub declared_rule: Option<String>,
    /// Level names in order; one level when absent.
    #[serde(default)]
    pub levels: Vec<String>,
}

/// POST /badges/programs: a program defines one of its own badges.
pub async fn program_create(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ProgramDefRequest>,
) -> ApiResult<(StatusCode, Json<BadgeDef>)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_PROGRAMS)?;
    let owned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM badge_defs WHERE program_pubkey = $1")
            .bind(&user.public_key)
            .fetch_one(&state.db)
            .await
            .map_err(db_err)?;
    if owned >= PROGRAM_BADGE_CAP {
        return Err((
            StatusCode::CONFLICT,
            format!("A program may define at most {PROGRAM_BADGE_CAP} badges"),
        ));
    }
    let names = if req.levels.is_empty() {
        vec![req.name.clone()]
    } else {
        req.levels.clone()
    };
    let as_def = DefRequest {
        name: req.name,
        icon: req.icon,
        description: req.description,
        rule: "manual".to_string(),
        role_id: None,
        keep_while: false,
        // The program decides who reaches a level; the order is all that matters.
        levels: names
            .into_iter()
            .enumerate()
            .map(|(i, n)| BadgeLevel {
                level: 0,
                name: n,
                threshold: i as i64,
            })
            .collect(),
    };
    validate(&as_def)?;
    if req.declared_rule.as_ref().is_some_and(|d| d.len() > 280) {
        return Err((
            StatusCode::BAD_REQUEST,
            "declared_rule is at most 280 chars".to_string(),
        ));
    }
    let id = insert_def(
        &state,
        &as_def,
        Some(&user.public_key),
        req.declared_rule.as_deref(),
    )
    .await?;
    let def = load_def(&state.db, &id).await?;
    Ok((StatusCode::CREATED, Json(full_def(&state.db, def).await?)))
}

async fn owned_by(state: &AppState, id: &str, program: &str) -> ApiResult<DefRow> {
    let def = load_def(&state.db, id).await?;
    if def.program_pubkey.as_deref() != Some(program) {
        return Err((
            StatusCode::FORBIDDEN,
            "Not this program's badge".to_string(),
        ));
    }
    Ok(def)
}

#[derive(Deserialize)]
pub struct ProgramGrant {
    pub subject: String,
    #[serde(default)]
    pub level: Option<i32>,
}

/// POST /badges/programs/:id/grant
pub async fn program_grant(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ProgramGrant>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_PROGRAMS)?;
    let def = owned_by(&state, &id, &user.public_key).await?;
    // An admin hid it: the catalogue does not show it, and nobody new gets it.
    if def.hidden {
        return Err((StatusCode::CONFLICT, "This badge is hidden".to_string()));
    }
    program_over_budget(&state, &user.public_key)?;
    let levels = levels_of(&state.db, &id).await?;
    let level = pick_level(&levels, req.level)?;
    let held: Option<i32> = sqlx::query_scalar(
        "SELECT level FROM badge_awards WHERE badge_id = $1 AND subject_pubkey = $2",
    )
    .bind(&id)
    .bind(&req.subject)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    if held == Some(level.level) {
        return Ok(StatusCode::NO_CONTENT);
    }
    award(&state, &def, level, &req.subject).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /badges/programs/:id/awards/:pubkey
pub async fn program_revoke(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((id, pubkey)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_PROGRAMS)?;
    owned_by(&state, &id, &user.public_key).await?;
    program_over_budget(&state, &user.public_key)?;
    unaward(&state, &id, &pubkey).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /badges/programs/:id: a program retires its own badge.
pub async fn program_delete(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(BADGES_PROGRAMS)?;
    owned_by(&state, &id, &user.public_key).await?;
    delete_def_and_revoke(&state, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
