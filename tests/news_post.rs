use axum::http::StatusCode;
use backend_nextlevelcodeblog::{
    config::init_logger,
    domains::{
        posts::model::{NewsPost, PostCommentWithComment},
        users::model::{AuthProvider, CreateUser, UserRole},
    },
};
use sqlx::PgPool;

use crate::common::{
    fixtures::create_user_test,
    test_state::{generate_test_token, test_server, ConfigTest},
};

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn news_post_test(pg_pool: PgPool) {
    init_logger();
    let config_test = ConfigTest::init();
    let user = create_user_test(
        &pg_pool,
        &CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: config_test.test_email,
            email_verified: true,
            google_sub: None,
            name: config_test.test_name,
            password_hash: Some(config_test.test_password),
            picture: None,
            token_expires_at: None,
            verification_token: Some(config_test.test_verification_token),
        },
        UserRole::User,
    )
    .await
    .unwrap();
    let server = test_server(&pg_pool).await;

    let token = generate_test_token(&pg_pool, user.id).await;

    server
        .post("/api/posts/create-post")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "title": "Test Post",
            "url": "test-post",
            "description": "This is a test post content.",
        }))
        .await
        .assert_status_success();

    let response = server
        .get("/api/posts/get-posts")
        .add_header("Authorization", format!("Bearer {}", token))
        .await;

    response.assert_status_ok();

    let posts: Vec<NewsPost> = response.json();

    server
        .post("/api/posts/create-comment")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "id": posts[0].id,
            "content": "This is a test comment.",
        }))
        .await
        .assert_status_success();

    let response = server
        .get("/api/posts/get-all-posts-with-comments")
        .add_header("Authorization", format!("Bearer {}", token))
        .await;

    response.assert_status_ok();

    let posts: Vec<PostCommentWithComment> = response.json();

    server
        .get("/api/posts/get-posts-with-comments")
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .get(&format!(
            "/api/posts/get-post-with-comments-by-id/{}",
            posts[0].post_id
        ))
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status_ok();

    server
        .put(&format!("/api/posts/update-post/{}", posts[0].post_id))
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "title": "Updated Post",
            "url": "updated-post",
            "description": "This is an updated post content.",
        }))
        .await
        .assert_status_success();

    server
        .put(&format!(
            "/api/posts/update-comment/{}",
            posts[0].comment_id.unwrap()
        ))
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "content": "This is a test comment.",
        }))
        .await
        .assert_status_ok();

    server
        .delete(&format!(
            "/api/posts/delete-comment/{}",
            posts[0].comment_id.unwrap()
        ))
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .delete(&format!("/api/posts/delete-post/{}", posts[0].post_id))
        .add_header("Authorization", format!("Bearer {}", token))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}
