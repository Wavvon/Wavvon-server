use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Profile an app declares for itself at registration time.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppMeta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<AppCommandDef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Mini-app / game-modal registration (mini-apps.md, apps.md).
    /// Absent = this app has no interactive-UI surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mini_app_url: Option<String>,
    /// Requests camera access for the mini-app webview. Still gated on the
    /// hub operator's `apps_allow_camera` setting at `app_join` time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_camera: Option<bool>,
    /// Profile-declared game descriptor (apps.md §11): lets
    /// a hub app listing show a Play affordance for this bot without
    /// a live launch-card message in view. Absent = this bot has no game to
    /// advertise. Independent of the per-message `game` launch card
    /// (`AppResponse.game`) -- this one lives on the profile, not a message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game: Option<GameLaunchCard>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppCommandDef {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<i64>,
}

// ---------------------------------------------------------------------------
// Directory / profile types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppProfile {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    pub capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// Event subscription
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppSubscription {
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Slash-command invocation envelope (hub → app webhook)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthorInfo {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashInvocation {
    #[serde(rename = "type")]
    pub kind: String, // always "slash_command"
    pub hub_url: String,
    pub channel_id: String,
    pub message_id_hint: String,
    pub author: AuthorInfo,
    pub command: String,
    pub args_raw: String,
    pub args_tokens: Vec<String>,
}

// ---------------------------------------------------------------------------
// Component interaction envelope (hub → app webhook)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentInteraction {
    #[serde(rename = "type")]
    pub kind: String, // always "component_interaction"
    pub hub_url: String,
    pub channel_id: String,
    pub message_id: String,
    pub custom_id: String,
    pub values: Vec<String>,
    pub user: AuthorInfo,
}

// ---------------------------------------------------------------------------
// App response types (app → hub, synchronous)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppReaction {
    pub message_id: String,
    pub emoji: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbedField {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbedFooter {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Embed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<EmbedField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SelectOption {
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppComponent {
    #[serde(rename = "type")]
    pub kind: String, // "button" or "select"
    pub custom_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOption>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentRow {
    #[serde(rename = "type")]
    pub kind: String, // always "row"
    pub components: Vec<AppComponent>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppReply {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeds: Option<Vec<Embed>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<AppReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<AppReaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
    /// Game-modal launch card (apps.md §2, §6 Phase 1 item
    /// 3): a "Play" CTA attached to `reply`'s message. Baseline UI -- no
    /// capability grant needed to render the card itself; opening the
    /// webview it points at is what `can_use_interactive_ui` gates
    /// (`app_join`, routes/ws/handlers/mini_app.rs). Ignored if `reply`
    /// is absent -- there is no message for the card to attach to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game: Option<GameLaunchCard>,
}

/// An app-authored "Play" launch card (apps.md §2).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GameLaunchCard {
    pub entry_url: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Component response types (app → hub, on component interaction)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EphemeralReply {
    pub body: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<ComponentUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_reply: Option<EphemeralReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
}

// ---------------------------------------------------------------------------
// Hub event push (hub → app WebSocket)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HubEvent {
    #[serde(rename = "type")]
    pub kind: String, // always "hub_event"
    pub event: String,
    pub hub_url: String,
    pub at: i64,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Lifecycle messages (hub → app WebSocket)
// ---------------------------------------------------------------------------
