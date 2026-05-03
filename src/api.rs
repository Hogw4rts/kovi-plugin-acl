use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use kovi::bot::runtimebot::kovi_api::{AccessControlMode, SetAccessControlList};
use kovi::RuntimeBot;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

// --- Shared state ---

#[derive(Clone)]
pub struct AppState {
    pub bot: Arc<RuntimeBot>,
    pub auth: crate::auth::AuthState,
    pub start_time: DateTime<Utc>,
    pub data_path: PathBuf,
}

// --- API types ---

#[derive(Serialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub access_control: bool,
    pub list_mode: String,
    pub groups: Vec<i64>,
    pub friends: Vec<i64>,
}

#[derive(Deserialize)]
pub struct AclToggle {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ModeChange {
    pub mode: String,
}

#[derive(Deserialize)]
pub struct ListEntry {
    pub id: i64,
}

#[derive(Deserialize)]
pub struct BatchEntries {
    pub ids: Vec<i64>,
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub start_time: DateTime<Utc>,
    pub uptime_secs: i64,
    pub plugin_count: usize,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub onebot_version: serde_json::Value,
    pub main_admin: i64,
    pub admins: Vec<i64>,
}

const SELF_NAME: &str = env!("CARGO_PKG_NAME");

// --- Error type ---

enum AppError {
    Internal(String),
    NotFound(&'static str),
    BadRequest(String),
    TooManyRequests(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::Internal(detail) => {
                kovi::log::error!("ACL API: internal error: {}", detail);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

// --- Helpers ---

pub fn mode_to_string(mode: &AccessControlMode) -> String {
    match mode {
        AccessControlMode::WhiteList => "whitelist".to_string(),
        AccessControlMode::BlackList => "blacklist".to_string(),
    }
}

pub fn string_to_mode(s: &str) -> Option<AccessControlMode> {
    match s {
        "whitelist" => Some(AccessControlMode::WhiteList),
        "blacklist" => Some(AccessControlMode::BlackList),
        _ => None,
    }
}

fn map_plugin_info(p: &kovi::plugin::PluginInfo) -> PluginInfo {
    PluginInfo {
        name: p.name.clone(),
        version: p.version.clone(),
        enabled: p.enabled,
        access_control: p.access_control,
        list_mode: mode_to_string(&p.list_mode),
        groups: p.access_list.groups.iter().copied().collect(),
        friends: p.access_list.friends.iter().copied().collect(),
    }
}

fn find_plugin(bot: &RuntimeBot, name: &str) -> Result<PluginInfo, AppError> {
    let plugins = bot
        .get_plugin_info()
        .map_err(|e| AppError::Internal(format!("get_plugin_info: {}", e)))?;
    match plugins.iter().find(|p| p.name == name) {
        Some(p) => Ok(map_plugin_info(p)),
        None => Err(AppError::NotFound("plugin not found")),
    }
}

fn check_self(name: &str) -> Result<(), AppError> {
    if name == SELF_NAME {
        Err(AppError::BadRequest("cannot modify self".to_string()))
    } else {
        Ok(())
    }
}

/// Macro: standard ACL mutation pattern — check self, call bot, persist, return ok.
/// Captures the error from the bot call and logs it before returning BadRequest.
macro_rules! acl_write {
    ($state:expr, $name:expr, $log_label:literal, $bot_call:expr) => {{
        check_self(&$name)?;
        $bot_call.map_err(|e| {
            kovi::log::warn!($log_label, e);
            AppError::BadRequest("bad request".to_string())
        })?;
        crate::persist::save(&$state.bot, &$state.data_path);
    }};
}

/// Macro: standard plugin-management pattern — check self, call bot, no persist.
macro_rules! plugin_op {
    ($state:expr, $name:expr, $log_label:literal, $bot_call:expr) => {{
        check_self(&$name)?;
        $bot_call.map_err(|e| {
            kovi::log::warn!($log_label, e);
            AppError::BadRequest("bad request".to_string())
        })?;
    }};
}

// --- Router ---

pub fn router() -> Router<AppState> {
    Router::new()
        // ACL
        .route("/api/plugins", get(list_plugins))
        .route("/api/plugins/{name}", get(get_plugin))
        .route("/api/plugins/{name}/acl", post(set_acl_toggle))
        .route("/api/plugins/{name}/mode", post(set_acl_mode))
        .route("/api/plugins/{name}/groups", post(add_group).delete(remove_group))
        .route("/api/plugins/{name}/groups/batch", post(add_groups_batch).delete(remove_groups_batch))
        .route("/api/plugins/{name}/friends", post(add_friend).delete(remove_friend))
        .route("/api/plugins/{name}/friends/batch", post(add_friends_batch).delete(remove_friends_batch))
        // Plugin management
        .route("/api/plugins/{name}/enable", post(enable_plugin))
        .route("/api/plugins/{name}/disable", post(disable_plugin))
        .route("/api/plugins/{name}/restart", post(restart_plugin))
        // Auth
        .route("/api/password", post(change_password))
        .route("/api/reset-password", post(reset_password))
        // System
        .route("/api/system", get(system_info))
}

// --- ACL handlers ---

async fn list_plugins(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let plugins = state
        .bot
        .get_plugin_info()
        .map_err(|e| AppError::Internal(format!("get_plugin_info: {}", e)))?;
    let list: Vec<PluginInfo> = plugins
        .iter()
        .filter(|p| p.name != SELF_NAME)
        .map(map_plugin_info)
        .collect();
    Ok(Json(list))
}

async fn get_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    check_self(&name)?;
    let info = find_plugin(&state.bot, &name)?;
    Ok(Json(info))
}

async fn set_acl_toggle(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<AclToggle>,
) -> Result<impl IntoResponse, AppError> {
    acl_write!(
        state,
        name,
        "ACL API: set_plugin_access_control failed: {}",
        state.bot.set_plugin_access_control(&name, body.enabled)
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn set_acl_mode(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<ModeChange>,
) -> Result<impl IntoResponse, AppError> {
    check_self(&name)?;
    let mode = string_to_mode(&body.mode)
        .ok_or_else(|| AppError::BadRequest("mode must be 'whitelist' or 'blacklist'".to_string()))?;
    let mode_str = mode_to_string(&mode);
    // Save current list under current mode BEFORE switching
    crate::persist::save(&state.bot, &state.data_path);
    state
        .bot
        .set_plugin_access_control_mode(&name, mode)
        .map_err(|e| {
            kovi::log::warn!("ACL API: set_plugin_access_control_mode failed: {}", e);
            AppError::BadRequest("bad request".to_string())
        })?;
    // Load and apply the new mode's saved list
    crate::persist::apply_mode_list(&state.bot, &name, &mode_str, &state.data_path);
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn add_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<ListEntry>,
) -> Result<impl IntoResponse, AppError> {
    acl_write!(
        state,
        name,
        "ACL API: add_group failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, true, SetAccessControlList::Add(body.id))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<ListEntry>,
) -> Result<impl IntoResponse, AppError> {
    acl_write!(
        state,
        name,
        "ACL API: remove_group failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, true, SetAccessControlList::Remove(body.id))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn add_groups_batch(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<BatchEntries>,
) -> Result<impl IntoResponse, AppError> {
    if body.ids.is_empty() {
        return Err(AppError::BadRequest("ids cannot be empty".to_string()));
    }
    acl_write!(
        state,
        name,
        "ACL API: add_groups_batch failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, true, SetAccessControlList::Adds(body.ids))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_groups_batch(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<BatchEntries>,
) -> Result<impl IntoResponse, AppError> {
    if body.ids.is_empty() {
        return Err(AppError::BadRequest("ids cannot be empty".to_string()));
    }
    acl_write!(
        state,
        name,
        "ACL API: remove_groups_batch failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, true, SetAccessControlList::Removes(body.ids))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn add_friend(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<ListEntry>,
) -> Result<impl IntoResponse, AppError> {
    acl_write!(
        state,
        name,
        "ACL API: add_friend failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, false, SetAccessControlList::Add(body.id))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_friend(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<ListEntry>,
) -> Result<impl IntoResponse, AppError> {
    acl_write!(
        state,
        name,
        "ACL API: remove_friend failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, false, SetAccessControlList::Remove(body.id))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn add_friends_batch(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<BatchEntries>,
) -> Result<impl IntoResponse, AppError> {
    if body.ids.is_empty() {
        return Err(AppError::BadRequest("ids cannot be empty".to_string()));
    }
    acl_write!(
        state,
        name,
        "ACL API: add_friends_batch failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, false, SetAccessControlList::Adds(body.ids))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_friends_batch(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<BatchEntries>,
) -> Result<impl IntoResponse, AppError> {
    if body.ids.is_empty() {
        return Err(AppError::BadRequest("ids cannot be empty".to_string()));
    }
    acl_write!(
        state,
        name,
        "ACL API: remove_friends_batch failed: {}",
        state
            .bot
            .set_plugin_access_control_list(&name, false, SetAccessControlList::Removes(body.ids))
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

// --- Plugin management handlers ---

async fn enable_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    plugin_op!(
        state,
        name,
        "ACL API: enable_plugin failed: {}",
        state.bot.enable_plugin(&name)
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn disable_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    plugin_op!(
        state,
        name,
        "ACL API: disable_plugin failed: {}",
        state.bot.disable_plugin(&name)
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn restart_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    plugin_op!(
        state,
        name,
        "ACL API: restart_plugin failed: {}",
        state.bot.restart_plugin(&name).await
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

// --- Auth handlers ---

async fn change_password(
    State(state): State<AppState>,
    Json(body): Json<crate::auth::ChangePasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    match crate::auth::change_password(&state, &body.current, &body.new).await {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true }))),
        Err(msg) => Err(AppError::BadRequest(msg)),
    }
}

async fn reset_password(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<crate::auth::ResetPasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    match crate::auth::reset_password_with_code(&state.auth, addr, &body.code, &body.new).await {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true }))),
        Err((status, msg)) => match status {
            StatusCode::TOO_MANY_REQUESTS => Err(AppError::TooManyRequests(msg)),
            _ => Err(AppError::BadRequest(msg)),
        },
    }
}

// --- System status handlers ---

async fn system_info(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let plugins = state
        .bot
        .get_plugin_info()
        .map_err(|e| AppError::Internal(format!("get_plugin_info: {}", e)))?;
    let uptime = (Utc::now() - state.start_time).num_seconds();

    let onebot_version = match state.bot.get_version_info().await {
        Ok(resp) => resp.data,
        Err(e) => {
            kovi::log::warn!("ACL API: get_version_info failed: {}", e);
            serde_json::json!(null)
        }
    };

    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();

    let (main_admin, admins) = match state.bot.get_all_admin() {
        Ok(list) => {
            let main = list.first().copied().unwrap_or(0);
            let deputy = if list.len() > 1 { list[1..].to_vec() } else { vec![] };
            (main, deputy)
        }
        Err(_) => (0, vec![]),
    };

    Ok(Json(SystemInfo {
        start_time: state.start_time,
        uptime_secs: uptime,
        plugin_count: plugins.len(),
        memory_used_mb: sys.used_memory() / 1024 / 1024,
        memory_total_mb: sys.total_memory() / 1024 / 1024,
        onebot_version,
        main_admin,
        admins,
    }))
}
