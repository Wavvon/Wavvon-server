//! The permission catalogue, served so clients stop carrying their own copy.
//!
//! Before this, the catalogue existed in four places that disagreed
//! (permissions.md §0): the hub's list, the roles UI's list, the channel
//! overwrite UI's list, and the strings the code actually consulted. Six
//! permissions the hub enforced were missing from the roles UI; four that
//! nothing consulted were offered as checkboxes.
//!
//! One list now, and the scope travels with each id — so "which of these has a
//! channel dimension", a decision that used to live in a TypeScript comment,
//! is answered by the server that enforces it.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, Scope};
use crate::state::AppState;

#[derive(serde::Serialize)]
pub struct CatalogueEntry {
    pub id: String,
    /// `hub` or `hub_and_channel`. A client offering a `hub` entry as a channel
    /// overwrite gets a 400, so this is what its overwrite screen filters on.
    pub scope: Scope,
    /// The dotted prefix, so a UI can group without re-splitting the id and
    /// drifting from the catalogue. `moderation.ban.permanent` groups under
    /// `moderation`.
    pub group: String,
}

#[derive(serde::Serialize)]
pub struct CatalogueResponse {
    pub permissions: Vec<CatalogueEntry>,
}

/// GET /permissions
///
/// Readable by any member. It is a list of what this hub *can* express, not of
/// what the caller holds — the roles screen needs it to render checkboxes for
/// roles the caller may be allowed to edit, and `/permissions/why` answers the
/// question about a specific member.
pub async fn get_catalogue(_user: AuthUser) -> Json<CatalogueResponse> {
    Json(CatalogueResponse {
        permissions: permissions::CATALOGUE
            .iter()
            .map(|p| CatalogueEntry {
                id: p.id.to_string(),
                scope: p.scope,
                group: p.id.split('.').next().unwrap_or(p.id).to_string(),
            })
            .collect(),
    })
}

#[derive(serde::Deserialize)]
pub struct WhyQuery {
    pub permission: String,
    /// Absent asks the hub-wide question; present folds the channel's ancestor
    /// chain in, which is the only form an operator ever actually asks.
    #[serde(default)]
    pub channel_id: Option<String>,
}

#[derive(serde::Serialize)]
pub struct WhySource {
    pub role_id: String,
    pub role_name: String,
    /// `baseline` for a hub-wide grant, or `allow`/`deny` for an overwrite,
    /// with the channel it sits on.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
}

#[derive(serde::Serialize)]
pub struct WhyResponse {
    pub public_key: String,
    pub permission: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    pub allowed: bool,
    /// Set when the answer is "because they own the hub", in which case
    /// `sources` is empty and no role explains anything.
    pub is_owner: bool,
    /// Every row that bears on the answer, in the order they are folded:
    /// hub-wide baseline first, then the ancestor chain root → target.
    pub sources: Vec<WhySource>,
}

/// GET /permissions/why?permission=…&channel_id=…  (per member)
///
/// "Why can this member do X here", answering *role Moderators, allowed on
/// #general*. Two axes are debuggable by reading and not by guessing, and
/// every operator question about permissions is this question
/// (permissions.md §1.5).
pub async fn why(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(public_key): Path<String>,
    Query(q): Query<WhyQuery>,
) -> Result<Json<WhyResponse>, (StatusCode, String)> {
    // Reading someone else's grants is reading the roster; reading your own is
    // always allowed, the same shape as `/channels/{id}/my-permissions`.
    if public_key != user.public_key {
        let caller = permissions::user_permissions(&state.db, &user.public_key).await?;
        caller.require(permissions::MEMBERS_READ)?;
    }

    if permissions::scope_of(&q.permission).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unknown permission: {}", q.permission),
        ));
    }

    let baseline = permissions::user_permissions(&state.db, &public_key).await?;
    let effective = match &q.channel_id {
        Some(cid) => permissions::channel_permissions(&state.db, &public_key, cid).await?,
        None => permissions::user_permissions(&state.db, &public_key).await?,
    };

    let mut sources = Vec::new();
    if !baseline.is_owner {
        let role_ids: Vec<String> = baseline.roles.iter().map(|r| r.id.clone()).collect();
        let name_of = |id: &str| {
            baseline
                .roles
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.name.clone())
                .unwrap_or_default()
        };

        for role in &baseline.roles {
            let carried: Vec<String> = sqlx::query_scalar(
                "SELECT permission FROM role_permissions WHERE role_id = $1 AND permission = $2",
            )
            .bind(&role.id)
            .bind(&q.permission)
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if !carried.is_empty() {
                sources.push(WhySource {
                    role_id: role.id.clone(),
                    role_name: role.name.clone(),
                    kind: "baseline".to_string(),
                    channel_id: None,
                });
            }
        }

        if let Some(cid) = &q.channel_id {
            let chain = permissions::ancestor_chain(&state.db, cid).await?;
            let rows = permissions::fetch_overwrites(&state.db, &chain, &role_ids).await?;
            // Root → target, which is the order the fold applies them in, so
            // reading the list top to bottom is reading the resolution.
            for channel in &chain {
                for row in rows.iter().filter(|r| &r.channel_id == channel) {
                    if row.permission != q.permission {
                        continue;
                    }
                    sources.push(WhySource {
                        role_id: row.role_id.clone(),
                        role_name: name_of(&row.role_id),
                        kind: if row.allow { "allow" } else { "deny" }.to_string(),
                        channel_id: Some(channel.clone()),
                    });
                }
            }
        }
    }

    Ok(Json(WhyResponse {
        public_key,
        allowed: effective.has(&q.permission),
        is_owner: baseline.is_owner,
        permission: q.permission,
        channel_id: q.channel_id,
        sources,
    }))
}
