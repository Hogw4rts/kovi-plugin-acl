use crate::api;
use crate::auth;
use include_dir::{include_dir, Dir};
use kovi::RuntimeBot;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

static WEB_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

pub async fn start_with_start_time(bot: Arc<RuntimeBot>, start_time: chrono::DateTime<chrono::Utc>, data_path: PathBuf, auth_state: crate::auth::AuthState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u16 = std::env::var("ACL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5800);

    let app_state = api::AppState {
        bot,
        auth: auth_state,
        start_time,
        data_path,
    };

    kovi::log::info!("ACL WebUI config: port={}", port);

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    let app = axum::Router::new()
        .route("/api/login", axum::routing::post(auth::login_handler))
        .merge(
            api::router()
                .layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    auth_middleware,
                ))
                .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30))),
        )
        .fallback(serve_static)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    kovi::log::info!("ACL WebUI listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;

async fn auth_middleware(
    State(state): State<api::AppState>,
    req: Request<Body>,
    next: Next,
) -> impl axum::response::IntoResponse {
    if req.uri().path() == "/api/login" || req.uri().path() == "/api/reset-password" {
        return next.run(req).await;
    }

    let addr = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0);

    match auth::require_auth(req.headers(), &state, addr).await {
        Ok(()) => next.run(req).await,
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response(),
    }
}

async fn serve_static(req: Request<Body>) -> impl IntoResponse {
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = WEB_DIR.get_file(path) {
        let content_type = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, content_type.as_ref())],
            file.contents().to_vec(),
        ).into_response();
    }

    // SPA fallback
    if let Some(file) = WEB_DIR.get_file("index.html") {
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            file.contents().to_vec(),
        ).into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}