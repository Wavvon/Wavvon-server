//! ttt-bot: the Phase 1 demo game bot (bot-capability-layer.md §7).
//!
//! `/ttt @user` in a channel posts a launch card; both players click Play,
//! which opens the game modal (bot-mini-apps.md); the modal's WS session
//! exchanges moves with this process via the generic `mini_app_message`
//! relay. This bot owns all board state in memory -- the hub never sees a
//! move, only opaque JSON payloads (bot-capability-layer.md decision 4,
//! "the hub stays dumb about games").
//!
//! Wire types are hand-mirrored here rather than imported from `wavvon-hub`
//! (matching `demo-seed`'s convention) -- a real bot author has no
//! compile-time dependency on the hub crate at all.
//!
//! Config (env vars):
//!   HUB_URL         base URL of the hub (default: http://localhost:3000)
//!   BOT_BIND_ADDR   address this process's own tiny HTTP server binds to
//!                   (default: 127.0.0.1:8089)
//!   BOT_PUBLIC_URL  externally reachable base URL for that server, used as
//!                   both `webhook_url` and `mini_app_url` (default:
//!                   http://127.0.0.1:8089)
//!   IDENTITY_PATH   where to persist this bot's Ed25519 keypair (default:
//!                   ~/.wavvon/ttt-bot-identity.json)

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bot_kit::Lobby;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use wavvon_identity::Identity;

mod board;
use board::Symbol;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn identity_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("IDENTITY_PATH") {
        return std::path::PathBuf::from(p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".wavvon")
        .join("ttt-bot-identity.json")
}

// ---------------------------------------------------------------------------
// Wire types (hand-mirrored from the hub -- see module doc)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    token: String,
}

#[derive(Deserialize)]
struct InfoResponse {
    public_key: String,
}

#[derive(Deserialize)]
struct UserInfo {
    public_key: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct PostedMessage {
    id: String,
}

// ---------------------------------------------------------------------------
// Bot-owned game state
// ---------------------------------------------------------------------------

struct GameSession {
    message_id: String,
    /// pubkey playing X (the invoker) / O (the mentioned opponent).
    x_pubkey: String,
    o_pubkey: String,
    board: board::Board,
    turn: Symbol,
    finished: bool,
}

impl GameSession {
    fn symbol_of(&self, pubkey: &str) -> Option<Symbol> {
        if pubkey == self.x_pubkey {
            Some(Symbol::X)
        } else if pubkey == self.o_pubkey {
            Some(Symbol::O)
        } else {
            None
        }
    }

    fn pubkey_of(&self, sym: Symbol) -> &str {
        match sym {
            Symbol::X => &self.x_pubkey,
            Symbol::O => &self.o_pubkey,
        }
    }

    fn state_json(&self, viewer: &str) -> Value {
        let winner = board::winner(&self.board);
        json!({
            "board": self.board.iter().map(|c| c.map(|s| s.as_str())).collect::<Vec<_>>(),
            "turn": self.turn.as_str(),
            "you": self.symbol_of(viewer).map(Symbol::as_str),
            "finished": self.finished,
            "winner": winner.map(Symbol::as_str),
        })
    }
}

struct Ctx {
    http: reqwest::Client,
    hub_url: String,
    hub_pubkey: String,
    bot_pubkey: String,
    bot_token: String,
    /// One active game per channel (ponytail: a new `/ttt` in a channel with
    /// an unfinished game silently replaces it -- fine for a demo bot; add a
    /// "game already in progress" reply if that ever surprises someone).
    /// Roster maintenance (hello/bye/ping, ~30s timeout eviction) is
    /// `bot-kit`'s job (bot-capability-layer.md §10); this bot only owns the
    /// board via `GameSession`.
    sessions: Lobby<GameSession>,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hub_url = env_or("HUB_URL", "http://localhost:3000");
    let bind_addr = env_or("BOT_BIND_ADDR", "127.0.0.1:8089");
    let public_url = env_or("BOT_PUBLIC_URL", "http://127.0.0.1:8089");

    let (identity, created) = Identity::load_or_create(&identity_path())?;
    let bot_pubkey = identity.public_key_hex();
    if created {
        println!("Generated a new bot identity at {:?}", identity_path());
    }
    println!("Bot pubkey: {bot_pubkey}");
    println!(
        "Ask a hub admin to run: POST {hub_url}/bots  {{\"pubkey\": \"{bot_pubkey}\"}}  (needs manage_roles/admin)"
    );
    println!("Then grant the game-modal capability: PUT {hub_url}/admin/bots/{bot_pubkey}/capabilities  {{\"capabilities\": [\"can_use_interactive_ui\"]}}");

    let http = reqwest::Client::new();

    let hub_pubkey = fetch_hub_pubkey(&http, &hub_url).await?;
    let bot_token = authenticate(&http, &hub_url, &identity, &public_url).await?;
    println!("Authenticated with the hub.");

    let ctx = Arc::new(Ctx {
        http: http.clone(),
        hub_url: hub_url.clone(),
        hub_pubkey,
        bot_pubkey,
        bot_token,
        sessions: Lobby::with_default_timeout(),
    });

    let app = Router::new()
        .route("/webhook", post(webhook_handler))
        .route("/app", get(app_page))
        .with_state(ctx.clone());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("Serving webhook + mini-app on http://{bind_addr}");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("HTTP server error: {e}");
        }
    });

    // Minimal reconnect loop -- fixed delay, no backoff (ponytail: fine for a
    // demo process a human is watching; add jittered backoff if this ever
    // runs unattended).
    loop {
        if let Err(e) = run_ws_loop(&ctx).await {
            eprintln!("WS loop ended: {e}. Reconnecting in 3s.");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn fetch_hub_pubkey(http: &reqwest::Client, hub_url: &str) -> anyhow::Result<String> {
    let info: InfoResponse = http
        .get(format!("{hub_url}/info"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(info.public_key)
}

/// Challenge-response auth with `is_bot: true`, retrying while the bot
/// hasn't been invited yet (`403 bot_not_invited`) -- see bots.md §1.
async fn authenticate(
    http: &reqwest::Client,
    hub_url: &str,
    identity: &Identity,
    public_url: &str,
) -> anyhow::Result<String> {
    let pubkey = identity.public_key_hex();
    loop {
        let challenge: ChallengeResponse = http
            .post(format!("{hub_url}/auth/challenge"))
            .json(&json!({ "public_key": pubkey }))
            .send()
            .await?
            .json()
            .await?;
        let challenge_bytes = hex::decode(&challenge.challenge)?;
        let signature = identity.sign(&challenge_bytes);

        let resp = http
            .post(format!("{hub_url}/auth/verify"))
            .json(&json!({
                "public_key": pubkey,
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
                "is_bot": true,
                "bot_meta": {
                    "name": "Tic-Tac-Toe",
                    "webhook_url": format!("{public_url}/webhook"),
                    "mini_app_url": format!("{public_url}/app"),
                    "capabilities": ["can_use_interactive_ui"],
                    "commands": [
                        { "name": "ttt", "description": "Challenge a member to Tic-Tac-Toe", "args": "@user" }
                    ],
                },
            }))
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            println!("Not invited yet -- waiting for the admin to run POST /bots. Retrying in 5s.");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        let verify: VerifyResponse = resp.error_for_status()?.json().await?;
        return Ok(verify.token);
    }
}

async fn app_page() -> Html<&'static str> {
    Html(include_str!("game.html"))
}

// ---------------------------------------------------------------------------
// Slash-command webhook (hub -> bot, synchronous)
// ---------------------------------------------------------------------------

async fn webhook_handler(
    State(ctx): State<Arc<Ctx>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sig_hex = headers
        .get("x-wavvon-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sig_ok = hex::decode(sig_hex)
        .ok()
        .map(|sig| wavvon_identity::verify_signature(&ctx.hub_pubkey, &body, &sig).is_ok())
        .unwrap_or(false);
    if !sig_ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
    }

    let invocation: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({}))).into_response(),
    };
    if invocation["type"].as_str() != Some("slash_command")
        || invocation["command"].as_str() != Some("ttt")
    {
        return Json(json!({})).into_response();
    }

    let channel_id = invocation["channel_id"].as_str().unwrap_or("").to_string();
    let invoker = invocation["author"]["pubkey"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let mention = invocation["args_raw"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();

    let reply = handle_ttt_command(&ctx, &channel_id, &invoker, &mention).await;
    match reply {
        Some(err_body) => {
            Json(json!({ "reply": { "body": err_body }, "ephemeral": true })).into_response()
        }
        None => Json(json!({})).into_response(),
    }
}

/// Returns `Some(error message)` to reply ephemerally, or `None` on success
/// (the launch-card message was already posted directly).
async fn handle_ttt_command(
    ctx: &Ctx,
    channel_id: &str,
    invoker: &str,
    mention: &str,
) -> Option<String> {
    if channel_id.is_empty() || invoker.is_empty() {
        return Some("Something went wrong reading that command.".to_string());
    }
    let target = mention.trim_start_matches('@');
    if target.is_empty() {
        return Some("Usage: /ttt @user".to_string());
    }

    let opponent = resolve_opponent(ctx, channel_id, target).await;
    let opponent = match opponent {
        Some(p) if p == invoker => {
            return Some("You can't challenge yourself.".to_string());
        }
        Some(p) => p,
        None => return Some(format!("Couldn't find {mention} in this channel.")),
    };

    let content = "Tic-Tac-Toe: click Play to join!".to_string();
    let posted: reqwest::Result<reqwest::Response> = ctx
        .http
        .post(format!("{}/channels/{channel_id}/messages", ctx.hub_url))
        .bearer_auth(&ctx.bot_token)
        .json(&json!({
            "content": content,
            "game": {
                "entry_url": format!("{}/app", public_url_from_token(ctx)),
                "name": "Tic-Tac-Toe",
                "description": "1v1",
            },
        }))
        .send()
        .await;

    let resp = match posted {
        Ok(r) if r.status().is_success() => r,
        _ => return Some("Failed to start the game.".to_string()),
    };
    let posted: PostedMessage = match resp.json().await {
        Ok(p) => p,
        Err(_) => return Some("Failed to start the game.".to_string()),
    };

    let session = GameSession {
        message_id: posted.id,
        x_pubkey: invoker.to_string(),
        o_pubkey: opponent,
        board: Default::default(),
        turn: Symbol::X,
        finished: false,
    };
    ctx.sessions.start(channel_id.to_string(), session);

    None
}

/// `entry_url` is cosmetic (the live web client re-opens via `bot_app_join`,
/// not by navigating to it -- see packages/ui GameCard.tsx), but we still
/// want it to point somewhere real. We don't have BOT_PUBLIC_URL threaded
/// into `Ctx` separately from mini_app_url, so just reconstruct it: the
/// mini_app_url we registered at auth time is `{public_url}/app`, and this
/// bot doesn't change it at runtime, so read it back from env directly.
fn public_url_from_token(_ctx: &Ctx) -> String {
    env_or("BOT_PUBLIC_URL", "http://127.0.0.1:8089")
}

/// Resolves `@display_name` (or a bare 64-hex pubkey) to a member of
/// `channel_id`.
async fn resolve_opponent(ctx: &Ctx, channel_id: &str, mention: &str) -> Option<String> {
    if mention.len() == 64 && mention.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(mention.to_string());
    }
    let members: Vec<UserInfo> = ctx
        .http
        .get(format!("{}/channels/{channel_id}/members", ctx.hub_url))
        .bearer_auth(&ctx.bot_token)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;

    members
        .into_iter()
        .find(|m| {
            m.display_name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(mention))
                .unwrap_or(false)
        })
        .map(|m| m.public_key)
}

// ---------------------------------------------------------------------------
// WS loop: the bot's live session, receives mini_app_message moves
// ---------------------------------------------------------------------------

async fn run_ws_loop(ctx: &Arc<Ctx>) -> anyhow::Result<()> {
    let ws_url = format!(
        "{}/ws?token={}",
        ctx.hub_url.replacen("http", "ws", 1),
        ctx.bot_token
    );
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await?;
    let (mut tx, mut rx) = ws.split();

    while let Some(msg) = rx.next().await {
        let msg = msg?;
        let text = match msg {
            WsMessage::Text(t) => t,
            _ => continue,
        };
        let frame: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if frame["type"].as_str() != Some("mini_app_message") {
            continue;
        }
        handle_mini_app_frame(ctx, &mut tx, &frame).await;
    }
    Ok(())
}

/// Outcome of applying one mini-app frame to a `GameSession`, computed
/// inside `Lobby::with_state` and carried out past the lock for the
/// (possibly async) fan-out below.
struct FrameOutcome {
    x_pubkey: String,
    o_pubkey: String,
    x_state: Value,
    o_state: Value,
    just_finished: bool,
    message_id: String,
    winner_pubkey: Option<String>,
}

async fn handle_mini_app_frame(ctx: &Arc<Ctx>, tx: &mut bot_kit::WsSink, frame: &Value) {
    let channel_id = match frame["channel_id"].as_str() {
        Some(c) => c.to_string(),
        None => return,
    };
    let from_pubkey = match frame["from_pubkey"].as_str() {
        Some(p) => p.to_string(),
        None => return,
    };
    let payload: Value = match frame["payload"]
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
    {
        Some(v) => v,
        None => return,
    };
    let kind = payload["kind"].as_str().unwrap_or("");
    let now = std::time::Instant::now();

    // Roster bookkeeping from the hello/bye/ping convention
    // (bot-capability-layer.md §10) -- ttt-bot doesn't act on roster
    // changes itself (it's a fixed 2-player game), but tracking them is
    // what makes a disconnect eventually get noticed instead of silently
    // leaving a dead session in memory.
    match kind {
        "hello" => {
            ctx.sessions.hello(&channel_id, &from_pubkey, None, now);
        }
        "bye" => {
            ctx.sessions.bye(&channel_id, &from_pubkey, now);
        }
        "ping" => {
            ctx.sessions.heartbeat(&channel_id, &from_pubkey, now);
        }
        _ => {}
    }

    let outcome = ctx
        .sessions
        .with_state(&channel_id, |session| -> Option<FrameOutcome> {
            let sender_symbol = session.symbol_of(&from_pubkey)?;

            let just_finished = match kind {
                "move" => {
                    if session.finished || sender_symbol != session.turn {
                        false
                    } else {
                        let cell = payload["cell"].as_u64()? as usize;
                        match board::validate_and_apply(
                            &mut session.board,
                            session.turn,
                            cell,
                            session.finished,
                        ) {
                            Ok(()) => {
                                if board::winner(&session.board).is_some()
                                    || board::is_full(&session.board)
                                {
                                    session.finished = true;
                                } else {
                                    session.turn = session.turn.other();
                                }
                                session.finished
                            }
                            Err(_) => false,
                        }
                    }
                }
                _ => false,
            };

            let x_pubkey = session.x_pubkey.clone();
            let o_pubkey = session.o_pubkey.clone();
            let x_state = session.state_json(&x_pubkey);
            let o_state = session.state_json(&o_pubkey);
            let winner_pubkey =
                board::winner(&session.board).map(|sym| session.pubkey_of(sym).to_string());

            Some(FrameOutcome {
                x_pubkey,
                o_pubkey,
                x_state,
                o_state,
                just_finished,
                message_id: session.message_id.clone(),
                winner_pubkey,
            })
        })
        .flatten();

    let Some(outcome) = outcome else {
        return;
    };

    // Push the updated state to both players (bot_kit's per-viewer send
    // loop, generalized from ttt-bot's original two-target `for` loop).
    let x_key = outcome.x_pubkey.clone();
    let o_key = outcome.o_pubkey.clone();
    bot_kit::broadcast(tx, &ctx.bot_pubkey, &channel_id, [x_key, o_key], |target| {
        if target == outcome.x_pubkey {
            outcome.x_state.clone()
        } else {
            outcome.o_state.clone()
        }
    })
    .await;

    if outcome.just_finished {
        let result_text = match &outcome.winner_pubkey {
            Some(pk) => format!("{pk} wins!"),
            None => "It's a draw!".to_string(),
        };
        let color = if outcome.winner_pubkey.is_some() {
            "#22c55e"
        } else {
            "#94a3b8"
        };

        let _ = ctx
            .http
            .patch(format!(
                "{}/channels/{channel_id}/messages/{}",
                ctx.hub_url, outcome.message_id
            ))
            .bearer_auth(&ctx.bot_token)
            .json(&json!({
                "content": "Tic-Tac-Toe — game over.",
                "embeds": [{ "title": "Tic-Tac-Toe", "description": result_text, "color": color }],
            }))
            .send()
            .await;

        let dismiss = json!({ "type": "bot_app_dismiss", "channel_id": channel_id });
        let _ = tx.send(WsMessage::Text(dismiss.to_string())).await;

        ctx.sessions.end(&channel_id);
    }
}
