use std::sync::Arc;

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use tracing::{info, instrument};

use crate::{
    app::AppState,
    domains::posts::query::{
        CreateNewsPostDto, PostCommentDto, UpdateNewsPost, UpdatePostCommentDto,
    },
    middleware::JWTAuthMiddeware,
    Result,
};

pub fn news_post_routes() -> Router {
    Router::new()
        .route("/get-posts", get(get_posts))
        .route(
            "/get-all-posts-with-comments",
            get(get_all_posts_with_comments),
        )
        .route(
            "/get-post-with-comments-by-id/{id}",
            get(get_posts_with_comments_by_id),
        )
        .route("/get-posts-with-comments", get(get_posts_with_comments))
        .route("/create-post", post(create_post))
        .route("/update-post/{id}", put(update_post))
        .route("/delete-post/{id}", delete(delete_post))
        .route("/create-comment", post(create_comment))
        .route("/update-comment/{id}", put(update_comment))
        .route("/delete-comment/{id}", delete(delete_comment))
}

#[instrument(name = "get_posts", skip(app_state))]
pub async fn get_posts(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    info!("Fetching all news posts");
    let posts = app_state.news_post_service.get_news_posts().await?;
    info!(count = posts.len(), "Fetched news posts");
    Ok((StatusCode::OK, Json(posts)))
}

#[instrument(name = "get_all_posts_with_comments", skip(app_state))]
pub async fn get_all_posts_with_comments(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    info!("Fetching all posts with comments");
    let posts = app_state
        .news_post_service
        .get_all_posts_with_comments()
        .await?;
    info!(count = posts.len(), "Fetched all posts with comments");
    Ok((StatusCode::OK, Json(posts)))
}

#[instrument(name = "get_posts_with_comments", skip(app_state))]
pub async fn get_posts_with_comments(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    info!("Fetching posts with comments");
    let posts = app_state
        .news_post_service
        .get_posts_with_comments()
        .await?;
    info!(count = posts.len(), "Fetched posts with comments");
    Ok((StatusCode::OK, Json(posts)))
}

#[instrument(name = "get_post_with_comments_by_id", skip(app_state))]
pub async fn get_posts_with_comments_by_id(
    Extension(app_state): Extension<Arc<AppState>>,
    Path(post_id): Path<String>,
) -> Result<impl IntoResponse> {
    info!(%post_id, "Fetching post with comments by ID");
    let posts = app_state
        .news_post_service
        .get_posts_with_comments_by_id(&post_id)
        .await?;
    info!(count = posts.len(), "Fetched post with comments");
    Ok((StatusCode::OK, Json(posts)))
}

#[instrument(name = "create_post", skip(app_state, jwt, news_post))]
pub async fn create_post(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(news_post): Json<CreateNewsPostDto>,
) -> Result<impl IntoResponse> {
    info!(%jwt.user.id, "Creating post");
    app_state
        .news_post_service
        .create_news_post(news_post, jwt.user.id)
        .await?;
    info!(%jwt.user.id, "Post created successfully");
    Ok(StatusCode::CREATED)
}

#[instrument(name = "update_post", skip(app_state, jwt, update_news_post))]
pub async fn update_post(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(news_post_id): Path<String>,
    Json(update_news_post): Json<UpdateNewsPost>,
) -> Result<impl IntoResponse> {
    info!(%news_post_id, "Updating post");
    app_state
        .news_post_service
        .update_news_post(
            jwt.user.id,
            &news_post_id,
            update_news_post.url.as_deref(),
            update_news_post.title.as_deref(),
            update_news_post.description.as_deref(),
        )
        .await?;
    info!(%news_post_id, "Post updated successfully");
    Ok(StatusCode::CREATED)
}

#[instrument(name = "delete_post", skip(app_state, jwt))]
pub async fn delete_post(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(post_id): Path<String>,
) -> Result<impl IntoResponse> {
    info!(%post_id, "Deleting post");
    app_state
        .news_post_service
        .delete_news_post(&post_id, jwt.user.id)
        .await?;
    info!(%post_id, "Post deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(name = "create_comment", skip(app_state, jwt, news_comment_post))]
pub async fn create_comment(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(news_comment_post): Json<PostCommentDto>,
) -> Result<impl IntoResponse> {
    info!(%jwt.user.id, post_id = %news_comment_post.id, "Creating comment");
    app_state
        .news_post_service
        .create_comment(
            &news_comment_post.id,
            &news_comment_post.content,
            jwt.user.id,
        )
        .await?;
    info!(post_id = %news_comment_post.id, "Comment created successfully");
    Ok(StatusCode::CREATED)
}

#[instrument(name = "update_comment", skip(app_state, jwt, news_comment_post))]
pub async fn update_comment(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(comment_id): Path<String>,
    Json(news_comment_post): Json<UpdatePostCommentDto>,
) -> Result<impl IntoResponse> {
    info!(%comment_id, "Updating comment");
    app_state
        .news_post_service
        .update_comment(
            &comment_id,
            news_comment_post.content.as_deref(),
            jwt.user.id,
        )
        .await?;
    info!(%comment_id, "Comment updated successfully");
    Ok(StatusCode::OK)
}

#[instrument(name = "delete_comment", skip(app_state, jwt))]
pub async fn delete_comment(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(comment_id): Path<String>,
) -> Result<impl IntoResponse> {
    info!(%comment_id, "Deleting comment");
    app_state
        .news_post_service
        .delete_comment(&comment_id, jwt.user.id)
        .await?;
    info!(%comment_id, "Comment deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}
