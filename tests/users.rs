use axum::http::StatusCode;
use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::users::model::{AuthProvider, CreateUser, UserRole},
};
use sqlx::PgPool;

use crate::common::{
    constants::{TEST_EMAIL, TEST_NAME, TEST_PASSWORD, TEST_VERIFICATION_TOKEN},
    fixtures::create_user_test,
    test_state::{generate_test_password_hash, generate_test_token, test_server},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn users_test(pg_pool: PgPool) {
    init_logger();

    let password = generate_test_password_hash(TEST_PASSWORD);

    let user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: TEST_EMAIL.to_string(),
            email_verified: true,
            google_sub: None,
            name: TEST_NAME.to_string(),
            password_hash: Some(password),
            picture: None,
            token_expires_at: None,
            verification_token: Some(TEST_VERIFICATION_TOKEN.to_string()),
        },
        UserRole::User,
    )
    .await
    .unwrap();

    let server = test_server(&pg_pool).await;

    let token = generate_test_token(&pg_pool, user.id).await;

    server
        .get("/api/users/me")
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .put("/api/users/update-username")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "name": "Updated Name",
            "password": TEST_PASSWORD,
        }))
        .await
        .assert_status_ok();

    server
        .put("/api/users/update-password")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "newPasswordConfirm": "Updated password",
            "newPassword": "Updated password",
            "oldPassword": TEST_PASSWORD,
        }))
        .await
        .assert_status_ok();

    server
        .delete(&format!("/api/users/delete/{}", user.id))
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}
