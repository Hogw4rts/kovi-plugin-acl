use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

const TOKEN_TTL_SECS: i64 = 86400; // 24 hours
const MAX_LOGIN_ATTEMPTS_PER_IP: u32 = 10;
const LOGIN_WINDOW_SECS: u64 = 60;
const MAX_FAILED_AUTH_PER_IP: u32 = 30;
const FAILED_AUTH_WINDOW_SECS: u64 = 60;
const RESET_CODE_TTL_SECS: i64 = 300; // 5 minutes
const MAX_RESET_ATTEMPTS_PER_IP: u32 = 5;
const RESET_IP_WINDOW_SECS: u64 = 300; // same as code TTL

// --- Persisted auth config ---

#[derive(Serialize, Deserialize, Clone)]
struct AuthConfig {
    password_hash: String,
    jwt_key: String,
}

// --- Runtime auth state ---

struct AuthInner {
    password_hash: [u8; 32],
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[derive(Clone)]
pub struct AuthState {
    inner: Arc<RwLock<AuthInner>>,
    data_path: std::path::PathBuf,
    login_guards: Arc<RwLock<HashMap<SocketAddr, LoginGuard>>>,
    failed_auth_guards: Arc<RwLock<HashMap<SocketAddr, LoginGuard>>>,
    reset_guards: Arc<RwLock<HashMap<SocketAddr, LoginGuard>>>,
    reset_codes: Arc<RwLock<HashMap<String, ResetCodeEntry>>>,
}

struct LoginGuard {
    attempts: u32,
    window_start: Instant,
}

struct ResetCodeEntry {
    admin_id: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    used: bool,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current: String,
    pub new: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub code: String,
    pub new: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: i64,
    pub iat: i64,
}

// --- Init ---

pub fn init_auth(data_path: &Path) -> AuthState {
    let auth_path = data_path.join("auth.json");

    let config = if auth_path.exists() {
        match std::fs::read_to_string(&auth_path) {
            Ok(s) => match serde_json::from_str::<AuthConfig>(&s) {
                Ok(c) => {
                    kovi::log::info!("ACL auth: loaded credentials from auth.json");
                    c
                }
                Err(e) => {
                    kovi::log::warn!("ACL auth: corrupt auth.json, regenerating: {}", e);
                    generate_and_save(&auth_path)
                }
            },
            Err(e) => {
                kovi::log::warn!("ACL auth: cannot read auth.json, regenerating: {}", e);
                generate_and_save(&auth_path)
            }
        }
    } else {
        generate_and_save(&auth_path)
    };

    let password_hash = match hex_to_bytes(&config.password_hash) {
        Ok(h) => h,
        Err(e) => {
            kovi::log::warn!("ACL auth: corrupt password_hash in auth.json ({}), regenerating", e);
            return init_auth_fresh(&auth_path, data_path);
        }
    };
    let jwt_key = match hex_to_bytes(&config.jwt_key) {
        Ok(k) => k,
        Err(e) => {
            kovi::log::warn!("ACL auth: corrupt jwt_key in auth.json ({}), regenerating", e);
            return init_auth_fresh(&auth_path, data_path);
        }
    };

    build_auth_state(password_hash, jwt_key, data_path)
}

fn init_auth_fresh(auth_path: &Path, data_path: &Path) -> AuthState {
    let config = generate_and_save(auth_path);
    let password_hash = hex_to_bytes(&config.password_hash).expect("generated hex is valid");
    let jwt_key = hex_to_bytes(&config.jwt_key).expect("generated hex is valid");
    build_auth_state(password_hash, jwt_key, data_path)
}

fn build_auth_state(password_hash: [u8; 32], jwt_key: [u8; 32], data_path: &Path) -> AuthState {
    AuthState {
        inner: Arc::new(RwLock::new(AuthInner {
            password_hash,
            encoding_key: EncodingKey::from_secret(&jwt_key),
            decoding_key: DecodingKey::from_secret(&jwt_key),
        })),
        data_path: data_path.to_path_buf(),
        login_guards: Arc::new(RwLock::new(HashMap::new())),
        failed_auth_guards: Arc::new(RwLock::new(HashMap::new())),
        reset_guards: Arc::new(RwLock::new(HashMap::new())),
        reset_codes: Arc::new(RwLock::new(HashMap::new())),
    }
}

fn generate_and_save(path: &Path) -> AuthConfig {
    let password = match std::env::var("ACL_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            let generated = generate_password(32);
            kovi::log::info!("ACL WebUI generated password: {}", generated);
            generated
        }
    };
    let password_hash = sha256(password.as_bytes());
    let jwt_key = generate_random_bytes(32);

    let config = AuthConfig {
        password_hash: bytes_to_hex(&password_hash),
        jwt_key: bytes_to_hex(&jwt_key),
    };

    if let Err(e) = kovi::utils::save_json_data(&config, path) {
        kovi::log::warn!("ACL auth: failed to save auth.json: {}", e);
    }

    config
}

// --- Password change ---

pub async fn change_password(
    state: &crate::api::AppState,
    current: &str,
    new: &str,
) -> Result<(), String> {
    let mut inner = state.auth.inner.write().await;

    let current_hash = sha256(current.as_bytes());
    if !constant_time_eq(&current_hash, &inner.password_hash) {
        return Err("current password is incorrect".to_string());
    }

    if new.len() < 6 {
        return Err("new password must be at least 6 characters".to_string());
    }

    let new_hash = sha256(new.as_bytes());
    let new_jwt_key = generate_random_bytes(32);

    let config = AuthConfig {
        password_hash: bytes_to_hex(&new_hash),
        jwt_key: bytes_to_hex(&new_jwt_key),
    };

    let auth_path = state.auth.data_path.join("auth.json");
    if let Err(e) = kovi::utils::save_json_data(&config, &auth_path) {
        return Err(format!("failed to save: {}", e));
    }

    inner.password_hash = new_hash;
    inner.encoding_key = EncodingKey::from_secret(&new_jwt_key);
    inner.decoding_key = DecodingKey::from_secret(&new_jwt_key);

    kovi::log::info!("ACL auth: password changed, all tokens invalidated");
    Ok(())
}

// --- Rate limiting ---

fn check_rate_limit(
    guards: &mut HashMap<SocketAddr, LoginGuard>,
    addr: SocketAddr,
    max_attempts: u32,
    window_secs: u64,
) -> bool {
    let now = Instant::now();
    let guard = guards.entry(addr).or_insert(LoginGuard {
        attempts: 0,
        window_start: now,
    });
    if now.duration_since(guard.window_start).as_secs() > window_secs {
        guard.attempts = 0;
        guard.window_start = now;
    }
    if guard.attempts >= max_attempts {
        return false;
    }
    guard.attempts += 1;
    true
}

fn prune_expired(guards: &mut HashMap<SocketAddr, LoginGuard>, window_secs: u64) {
    let now = Instant::now();
    guards.retain(|_, g| now.duration_since(g.window_start).as_secs() <= window_secs);
}

// --- Handlers ---

pub async fn login_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<crate::api::AppState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    {
        let mut guards = state.auth.login_guards.write().await;
        prune_expired(&mut guards, LOGIN_WINDOW_SECS);
        if !check_rate_limit(&mut guards, addr, MAX_LOGIN_ATTEMPTS_PER_IP, LOGIN_WINDOW_SECS) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "too many attempts, try again later" })),
            )
                .into_response();
        }
    }

    let inner = state.auth.inner.read().await;
    let input_hash = sha256(body.password.as_bytes());
    if !constant_time_eq(&input_hash, &inner.password_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid password" })),
        )
            .into_response();
    }

    let now = Utc::now().timestamp();
    let claims = Claims { iat: now, exp: now + TOKEN_TTL_SECS };
    let token = match encode(&Header::default(), &claims, &inner.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            kovi::log::error!("ACL auth: JWT encode failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal error" })),
            )
                .into_response();
        }
    };

    drop(inner);
    state.auth.login_guards.write().await.remove(&addr);

    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
}

pub async fn require_auth(
    headers: &HeaderMap,
    state: &crate::api::AppState,
    addr: Option<SocketAddr>,
) -> Result<(), StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => {
            if let Some(addr) = addr {
                let mut guards = state.auth.failed_auth_guards.write().await;
                prune_expired(&mut guards, FAILED_AUTH_WINDOW_SECS);
                if !check_rate_limit(&mut guards, addr, MAX_FAILED_AUTH_PER_IP, FAILED_AUTH_WINDOW_SECS) {
                    return Err(StatusCode::TOO_MANY_REQUESTS);
                }
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let inner = state.auth.inner.read().await;
    let validation = Validation::default();
    match decode::<Claims>(token, &inner.decoding_key, &validation) {
        Ok(_) => Ok(()),
        Err(_) => {
            drop(inner);
            if let Some(addr) = addr {
                let mut guards = state.auth.failed_auth_guards.write().await;
                prune_expired(&mut guards, FAILED_AUTH_WINDOW_SECS);
                if !check_rate_limit(&mut guards, addr, MAX_FAILED_AUTH_PER_IP, FAILED_AUTH_WINDOW_SECS) {
                    return Err(StatusCode::TOO_MANY_REQUESTS);
                }
            }
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// --- Reset code ---

/// Generate a 6-digit reset code for the given admin, store it, and return the code string.
pub async fn generate_reset_code(state: &AuthState, admin_id: i64) -> String {
    let code = generate_password(6);
    let mut codes = state.reset_codes.write().await;

    // Prune expired codes
    let now = chrono::Utc::now();
    codes.retain(|_, v| !v.used && (now - v.created_at).num_seconds() < RESET_CODE_TTL_SECS);

    // Invalidate any existing codes for this admin
    codes.retain(|_, v| v.admin_id != admin_id);

    codes.insert(
        code.clone(),
        ResetCodeEntry {
            admin_id,
            created_at: now,
            used: false,
        },
    );

    code
}

/// Verify a reset code and reset the password.
///
/// Rate-limited per IP (5 attempts / 5 min).  The code space is 16^6 and
/// each IP only gets a handful of guesses; brute-forcing is infeasible.
/// Returns `Ok(())` on success or `Err((StatusCode, String))`.
pub async fn reset_password_with_code(
    state: &AuthState,
    addr: SocketAddr,
    code: &str,
    new: &str,
) -> Result<(), (StatusCode, String)> {
    // Per-IP rate limiting (reuses the same guard pattern as login/auth)
    {
        let mut guards = state.reset_guards.write().await;
        prune_expired(&mut guards, RESET_IP_WINDOW_SECS);
        if !check_rate_limit(&mut guards, addr, MAX_RESET_ATTEMPTS_PER_IP, RESET_IP_WINDOW_SECS) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "too many attempts, try again later".to_string(),
            ));
        }
    }

    if new.len() < 6 {
        return Err((
            StatusCode::BAD_REQUEST,
            "new password must be at least 6 characters".to_string(),
        ));
    }

    // Validate code
    let admin_id = {
        let mut codes = state.reset_codes.write().await;
        let now = chrono::Utc::now();

        // Prune expired
        codes.retain(|_, v| !v.used && (now - v.created_at).num_seconds() < RESET_CODE_TTL_SECS);

        let entry = match codes.get_mut(code) {
            Some(e) => e,
            None => return Err((
                StatusCode::BAD_REQUEST,
                "invalid or expired reset code".to_string(),
            )),
        };

        if entry.used {
            return Err((
                StatusCode::BAD_REQUEST,
                "reset code already used".to_string(),
            ));
        }
        if (now - entry.created_at).num_seconds() > RESET_CODE_TTL_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                "reset code expired".to_string(),
            ));
        }

        // Mark used and return admin_id for logging
        entry.used = true;
        entry.admin_id
    };

    let mut inner = state.inner.write().await;
    let new_hash = sha256(new.as_bytes());
    let new_jwt_key = generate_random_bytes(32);

    let config = AuthConfig {
        password_hash: bytes_to_hex(&new_hash),
        jwt_key: bytes_to_hex(&new_jwt_key),
    };

    let auth_path = state.data_path.join("auth.json");
    if let Err(e) = kovi::utils::save_json_data(&config, &auth_path) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to save: {}", e)));
    }

    inner.password_hash = new_hash;
    inner.encoding_key = EncodingKey::from_secret(&new_jwt_key);
    inner.decoding_key = DecodingKey::from_secret(&new_jwt_key);

    // Clear rate limit on success
    state.reset_guards.write().await.remove(&addr);

    kovi::log::info!("ACL auth: password reset via code by admin {}", admin_id);
    Ok(())
}

// --- Crypto helpers ---

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex at byte {}: {}", i, e))?;
    }
    Ok(arr)
}

fn generate_password(len: usize) -> String {
    use uuid::Uuid;
    let mut hex = String::new();
    while hex.len() < len {
        hex.push_str(&Uuid::new_v4().simple().to_string());
    }
    hex.truncate(len);
    hex
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    use uuid::Uuid;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let uuid = Uuid::new_v4();
        bytes.extend_from_slice(uuid.as_bytes());
    }
    bytes.truncate(len);
    bytes
}
