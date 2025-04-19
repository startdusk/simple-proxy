use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{net::SocketAddr, sync::Arc};
use tracing::info;

#[derive(Debug, Serialize, Clone)]
struct User {
    id: u64,
    name: String,
    email: String,
    password: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

struct AppStateInner {
    next_id: AtomicU64,
    users: DashMap<u64, User>,
    argon2: Argon2<'static>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

impl AppState {
    fn new() -> Self {
        AppState {
            inner: Arc::new(AppStateInner {
                next_id: AtomicU64::new(1),
                users: DashMap::new(),
                argon2: Argon2::default(),
            }),
        }
    }

    fn get_user(&self, id: u64) -> Option<User> {
        self.inner.users.get(&id).map(|r| r.clone())
    }

    fn get_users(&self) -> Vec<User> {
        self.inner.users.iter().map(|r| r.clone()).collect()
    }

    fn create_user(&self, user: CreateUserRequest) -> Result<User, anyhow::Error> {
        let password_hash = hash_password(&self.inner.argon2, &user.password)?;

        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let user = User {
            id,
            name: user.name,
            email: user.email,
            password: password_hash.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.inner.users.insert(id, user.clone());
        Ok(user)
    }

    fn update_user(&self, id: u64, mut user: UpdateUserRequest) -> Option<User> {
        let mut entry = self.get_user(id)?;
        let now = Utc::now();

        if let Some(name) = user.name.take() {
            entry.name = name;
        }
        if let Some(email) = user.email.take() {
            entry.email = email;
        }
        if let Some(password) = user.password.take() {
            entry.password = hash_password(&self.inner.argon2, &password).ok()?;
        }

        entry.updated_at = now;

        self.inner.users.insert(id, entry.clone());
        Some(entry)
    }

    fn delete_user(&self, id: u64) -> Option<User> {
        self.inner.users.remove(&id).map(|(_, user)| user)
    }

    fn health_check(&self) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "status": "ok" }))
    }
}

fn hash_password(argon2: &Argon2<'static>, password: &str) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    Ok(password_hash.to_string())
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let app_state = AppState::new();

    let app = Router::new()
        .route("/users", get(get_users).post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/health", get(health_check))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<(StatusCode, Json<User>), (StatusCode, Json<serde_json::Value>)> {
    match state.get_user(id) {
        Some(user) => Ok((StatusCode::OK, Json(user))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "User not found" })),
        )),
    }
}

async fn get_users(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.get_users()))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<User>), (StatusCode, Json<serde_json::Value>)> {
    match state.create_user(payload) {
        Ok(user) => Ok((StatusCode::CREATED, Json(user))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<(StatusCode, Json<User>), (StatusCode, Json<serde_json::Value>)> {
    match state.update_user(id, payload) {
        Some(user) => Ok((StatusCode::OK, Json(user))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "User not found" })),
        )),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<(StatusCode, Json<User>), (StatusCode, Json<serde_json::Value>)> {
    match state.delete_user(id) {
        Some(user) => Ok((StatusCode::OK, Json(user))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "User not found" })),
        )),
    }
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    state.health_check()
}
