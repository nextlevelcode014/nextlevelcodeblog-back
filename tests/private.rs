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
    constants::{TEST_EMAIL, TEST_EMAIL_ADMIN, TEST_NAME, TEST_PASSWORD, TEST_VERIFICATION_TOKEN},
    fixtures::create_user_test,
    test_state::{generate_test_token, test_server},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn private_test(pg_pool: PgPool) {
    init_logger();
    let user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: TEST_EMAIL.to_string(),
            email_verified: true,
            google_sub: None,
            name: TEST_NAME.to_string(),
            password_hash: Some(TEST_PASSWORD.to_string()),
            picture: None,
            token_expires_at: None,
            verification_token: Some(TEST_VERIFICATION_TOKEN.to_string()),
        },
        UserRole::User,
    )
    .await
    .unwrap();

    let admin = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: TEST_EMAIL_ADMIN.to_string(),
            email_verified: true,
            google_sub: None,
            name: TEST_NAME.to_string(),
            password_hash: Some(TEST_PASSWORD.to_string()),
            picture: None,
            token_expires_at: None,
            verification_token: Some("kksksksksk".to_string()),
        },
        UserRole::Admin,
    )
    .await
    .unwrap();

    let server = test_server(&pg_pool).await;

    let token = generate_test_token(&pg_pool, admin.id).await;

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
