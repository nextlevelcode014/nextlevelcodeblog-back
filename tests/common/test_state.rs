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

use std::env::var;

#[derive(Debug, Clone)]
pub struct ConfigTest {
    pub test_name: String,
    pub test_email: String,
    pub test_password: String,
    pub test_verification_token: String,
    pub test_email_admin: String,
}

impl ConfigTest {
    pub fn init() -> ConfigTest {
        let test_name = var("TEST_NAME").expect("TEST_NAME must be set");
        let test_email = var("TEST_EMAIL").expect("TEST_EMAIL must be set");
        let test_password = var("TEST_PASSWORD").expect("TEST_PASSWORD must be set");
        let test_email_admin = var("TEST_EMAIL_ADMIN").expect("TEST_EMAIL_ADMIN must bet set");
        let test_verification_token =
            var("TEST_VERIFICATION_TOKEN").expect("TEST_VERIFICATION_TOKEN must bet set");

        ConfigTest {
            test_email,
            test_email_admin,
            test_password,
            test_verification_token,
            test_name,
        }
    }
}

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
        .generate_token(user_id.to_string(), 3600)
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
