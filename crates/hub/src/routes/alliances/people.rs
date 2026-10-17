// Alliance member discovery (alliance-member-discovery.md): browse the members
// of one allied hub who opted in. Read-through -- the owning hub answers from
// its own `users` table and nothing is copied to the asker.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::middleware::AuthUser;
use crate::routes::alliance_models::AlliancePerson;
use crate::routes::paging::{DEFAULT_LIMIT, MAX_LIMIT};
use crate::state::AppState;

use super::channels::peer_token;
use super::managers::require_alliance_manager;
use super::models::{caller_is_peer, require_alliance_visibility, MemberRow};

// `limit` and `cursor` are spelled out rather than flattened from `PageQuery`:
// serde_urlencoded cannot parse a flattened integer.
#[derive(Deserialize)]
pub struct PeopleQuery {
    /// Public key of the hub to ask; absent or this hub's own key = answer locally.
    hub: Option<String>,
    q: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct PeopleVisibilityRequest {
    visible: bool,
}

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

fn check_rate_limit(state: &AppState, caller: &str) -> Result<(), (StatusCode, String)> {
    const LIMIT: u32 = 60;
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    const EVICTION_THRESHOLD: usize = 2_000;

    let mut map = state
        .rate_limiters
        .alliance_people
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if map.len() >= EVICTION_THRESHOLD {
        map.retain(|_, (_, ts)| now.duration_since(*ts) <= WINDOW);
    }
    let entry = map.entry(caller.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > WINDOW {
        *entry = (0, now);
    }
    if entry.0 >= LIMIT {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()));
    }
    entry.0 += 1;
    Ok(())
}

/// GET /alliances/{id}/people?hub=&q=&limit=&cursor=
pub async fn get_alliance_people(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Query(params): Query<PeopleQuery>,
) -> Result<Json<Vec<AlliancePerson>>, (StatusCode, String)> {
    require_alliance_visibility(&state, &user.public_key, &alliance_id).await?;
    check_rate_limit(&state, &user.public_key)?;

    let own_key = state.hub_identity.public_key_hex();
    let target = params.hub.clone().unwrap_or_else(|| own_key.clone());

    // This hub has to be in the alliance either way: the mirror rows can
    // outlive a departure for a moment.
    let people_visible: Option<bool> = sqlx::query_scalar(
        "SELECT a.people_visible FROM alliances a
         WHERE a.id = $1
           AND EXISTS(SELECT 1 FROM alliance_members
                      WHERE alliance_id = a.id AND hub_public_key = $2)",
    )
    .bind(&alliance_id)
    .bind(&own_key)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    let Some(people_visible) = people_visible else {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    };

    let q = params
        .q
        .as_deref()
        .map(|s| s.chars().take(64).collect::<String>());
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    if target == own_key {
        // Same refusal whether the alliance is closed to people or does not
        // exist: the surface itself is what is withheld.
        if !people_visible {
            return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
        }
        return list_local(&state, q, params.cursor, limit).await;
    }

    // A peer asking about a third hub would turn this one into a relay.
    if caller_is_peer(&state, &user.public_key).await? {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    let member = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at
         FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2",
    )
    .bind(&alliance_id)
    .bind(&target)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or((
        StatusCode::NOT_FOUND,
        "Hub not in this alliance".to_string(),
    ))?;

    let token = peer_token(&state, &member)
        .await
        .ok_or((StatusCode::BAD_GATEWAY, "peer_unreachable".to_string()))?;

    // The viewer is deliberately not forwarded: the answering hub must not
    // learn who browses its people.
    let limit_s = limit.to_string();
    let mut query: Vec<(&str, &str)> = vec![("limit", &limit_s)];
    if let Some(q) = q.as_deref() {
        query.push(("q", q));
    }
    if let Some(c) = params.cursor.as_deref() {
        query.push(("cursor", c));
    }
    match state
        .federation_client
        .get_alliance_people(&member.hub_url, &token, &alliance_id, &target, &query)
        .await
    {
        Ok(Some(people)) => Ok(Json(people)),
        // Never an empty list: that would read as "nobody is there".
        Ok(None) => Err((StatusCode::CONFLICT, "peer_unsupported".to_string())),
        Err(e) => {
            tracing::warn!("alliance people from {} failed: {e}", member.hub_url);
            Err((StatusCode::BAD_GATEWAY, "peer_unreachable".to_string()))
        }
    }
}

/// Both switches, an unbanned member, and a designation on file -- all in the
/// SQL, before LIMIT, so a page is never short. The designation is what makes
/// "Message" work for every entry (§5).
async fn list_local(
    state: &AppState,
    q: Option<String>,
    cursor: Option<String>,
    limit: i64,
) -> Result<Json<Vec<AlliancePerson>>, (StatusCode, String)> {
    let search = q.map(|q| format!("%{q}%"));
    let rows = sqlx::query_as::<_, AlliancePerson>(
        "SELECT public_key, master_pubkey, display_name, avatar FROM (
             SELECT u.public_key, u.display_name, u.avatar,
                    COALESCE(u.master_pubkey,
                             (SELECT c.master_pubkey FROM subkey_certs c
                              WHERE c.subkey_pubkey = u.public_key LIMIT 1)) AS master_pubkey
             FROM users u
             WHERE u.is_member AND u.findable_by_allies
               AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key)
               AND ($1::text IS NULL OR u.display_name LIKE $1)
         ) t
         WHERE EXISTS (SELECT 1 FROM home_hub_designations d WHERE d.master_pubkey = t.master_pubkey)
           AND ($2::text IS NULL OR
                (COALESCE(display_name, ''), public_key) >
                ((SELECT COALESCE(display_name, '') FROM users WHERE public_key = $2), $2))
         ORDER BY COALESCE(display_name, ''), public_key
         LIMIT $3",
    )
    .bind(search.as_deref())
    .bind(cursor.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(rows))
}

/// PUT /alliances/{id}/people-visibility -- the alliance-level switch.
pub async fn set_people_visibility(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Json(req): Json<PeopleVisibilityRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_alliance_visibility(&state, &user.public_key, &alliance_id).await?;
    require_alliance_manager(&state, &user.public_key, &alliance_id).await?;

    let updated = sqlx::query("UPDATE alliances SET people_visible = $1 WHERE id = $2")
        .bind(req.visible)
        .bind(&alliance_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }
    Ok(StatusCode::NO_CONTENT)
}
