#![allow(unused)]

use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::users::model::{AuthProvider, CreateUser, UserRole},
};
use serde_json::json;
use sqlx::PgPool;

use crate::common::{
    constants::{TEST_EMAIL, TEST_NAME, TEST_PASSWORD, TEST_VERIFICATION_TOKEN},
    fixtures::create_user_test,
    test_state::test_server,
};

mod common;

#[sqlx::test(migrations = "./migrations")]
#[ignore = "Recaptcha"]
async fn auth_test(pg_pool: PgPool) {
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

    let server = test_server(&pg_pool).await;

    server
        .post("/api/auth/register")
        .json(&json!({
        "name": "Marcelo",
        "email": "teste@example.com",
        "password_hash": TEST_PASSWORD,
        "passwordConfirm": TEST_PASSWORD,
        }))
        .await
        .assert_status_success();

    let verify_email_res = server
        .get("/api/auth/verify-email?token=test_verification_token")
        .await;

    verify_email_res.assert_status_success();

    let login_res = server
        .post("/api/auth/login")
        .json(&json!({
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        }))
        .await;

    login_res.assert_status_ok();

    let forgot_password_res = server
        .post("/api/auth/forgot-password")
        .json(&json!({
        "email": TEST_EMAIL,
        }))
        .await;

    forgot_password_res.assert_status_ok();

    let reset_password_res = server
        .post("/api/auth/reset-password")
        .json(&json!({
            "token": TEST_VERIFICATION_TOKEN,
            "newPassword": "new_password",
            "confirmPassword": "new_password",
        }))
        .await;

    reset_password_res.assert_status_ok();
}
