#![allow(unused)]

use std::sync::Arc;

use axum_test::TestServer;
use backend_nextlevelcodeblog::{
    app::{build_app, build_app_state},
    config::Config,
    domains::auth::service::AuthService,
    infrastructure::db::PostgresRepo,
};
use sqlx::PgPool;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

pub async fn test_server(pool: &PgPool) -> TestServer {
    let config = Config::init();
    let state: Arc<_> = build_app_state(config, pool.clone()).await;
    let app = build_app(state);
    TestServer::new(app).unwrap()
}

pub async fn generate_test_token(pool: &PgPool, user_id: uuid::Uuid) -> String {
    let repo = PostgresRepo::new(pool.clone());

    let auth_service = AuthService::with_default_config(repo);
    auth_service
        .generate_token(&user_id.to_string(), 3600)
        .unwrap()
}
pub fn generate_test_password_hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("hash failed")
        .to_string();

    password_hash
}
