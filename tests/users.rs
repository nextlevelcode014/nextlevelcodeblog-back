use axum::http::StatusCode;
use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::users::model::{AuthProvider, CreateUser, UserRole},
};
use sqlx::PgPool;

use crate::common::{
    fixtures::create_user_test,
    test_state::{generate_test_password_hash, generate_test_token, test_server, ConfigTest},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
#[ignore = "Prod"]
async fn users_test(pg_pool: PgPool) {
    init_logger();

    let config_test = ConfigTest::init();
    let password = generate_test_password_hash(&config_test.test_password);

    let user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: config_test.test_email,
            email_verified: true,
            google_sub: None,
            name: config_test.test_name.to_owned(),
            password_hash: Some(password),
            picture: None,
            token_expires_at: None,
            verification_token: Some(config_test.test_password.to_owned()),
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
            "password": config_test.test_password,
        }))
        .await
        .assert_status_ok();

    server
        .post("/api/users/delete")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "password": config_test.test_password
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .delete("/api/users/google-user-delete")
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .put("/api/users/update-password")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "newPasswordConfirm": "Updated password",
            "newPassword": "Updated password",
            "oldPassword": config_test.test_password,
        }))
        .await
        .assert_status_ok();
}
