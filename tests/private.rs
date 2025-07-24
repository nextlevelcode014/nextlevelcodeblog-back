use axum::http::StatusCode;
use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::{
        posts::model::Category,
        users::model::{AuthProvider, CreateUser, UserRole},
    },
};
use serde_json::json;
use sqlx::PgPool;

use crate::common::{
    fixtures::create_user_test,
    test_state::{generate_test_token, test_server, ConfigTest},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn private_test(pg_pool: PgPool) {
    init_logger();
    let config_test = ConfigTest::init();

    let user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: config_test.test_email,
            email_verified: true,
            google_sub: None,
            name: config_test.test_name.to_owned(),
            password_hash: Some(config_test.test_password.to_owned()),
            picture: None,
            token_expires_at: None,
            verification_token: Some(config_test.test_password.to_owned()),
        },
        UserRole::User,
    )
    .await
    .unwrap();

    let admin = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: config_test.test_email_admin,
            email_verified: true,
            google_sub: None,
            name: config_test.test_name,
            password_hash: Some(config_test.test_password),
            picture: None,
            token_expires_at: None,
            verification_token: Some(config_test.test_verification_token),
        },
        UserRole::Admin,
    )
    .await
    .unwrap();

    let server = test_server(&pg_pool).await;

    let token = generate_test_token(&pg_pool, admin.id).await;

    server
        .get("/api/private/admin/health")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .get("/api/private/admin/users")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .post("/api/private/admin/create-category")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "name": "tech",
        }))
        .await
        .assert_status_success();

    let response = server
        .get("/api/private/admin/categories")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .await;

    response.assert_status_ok();

    let categories = response.json::<Vec<Category>>();

    server
        .put(&format!(
            "/api/private/admin/update-category/{}",
            categories[0].id
        ))
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "name": "updated-tech",
        }))
        .await
        .assert_status_success();

    server
        .delete(&format!(
            "/api/private/admin/delete-category/{}",
            categories[0].id
        ))
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .put("/api/private/admin/role")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "userId": user.id,
            "role": "Admin",
        }))
        .await
        .assert_status_success();

    server
        .delete("/api/private/admin/delete-user")
        .add_header("x-api-key", std::env::var("API_KEY").unwrap())
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "userId": user.id,
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}
