use axum::http::StatusCode;
use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::users::model::{AuthProvider, CreateUser, UserRole},
};
use sqlx::PgPool;

use crate::common::{
    fixtures::create_user_test,
    test_state::{generate_test_token, test_server, ConfigTest},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn google_users_test(pg_pool: PgPool) {
    init_logger();

    let config_test = ConfigTest::init();

    let google_user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Google,
            email: config_test.test_email,
            email_verified: true,
            google_sub: Some("dbebu294498bbbebebeb3bb3b3ss8h".to_owned()),
            name: config_test.test_name.to_owned(),
            password_hash: None,
            picture: None,
            token_expires_at: None,
            verification_token: Some(config_test.test_password.to_owned()),
        },
        UserRole::User,
    )
    .await
    .unwrap();

    let server = test_server(&pg_pool).await;

    let token = generate_test_token(&pg_pool, google_user.id).await;

    server
        .get("/api/users/me")
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .delete("/api/users/google-user-delete")
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}
