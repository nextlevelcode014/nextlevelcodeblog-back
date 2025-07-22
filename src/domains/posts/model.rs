use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct NewsPost {
    pub id: Uuid,
    pub title: String,
    pub url: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
    pub description: String,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct PostCommentWithComment {
    pub post_id: Uuid,
    pub title: String,
    pub url: String,
    pub description: String,
    pub post_created_at: DateTime<Utc>,
    pub author_name: String,
    pub comment_id: Option<Uuid>,
    pub comment_content: Option<String>,
    pub comment_created_at: Option<DateTime<Utc>>,
    pub commenter_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct CommentWithAuthor {
    pub id: Uuid,
    pub content: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct PostComment {
    pub id: Uuid,
    pub content: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct PostCommentWithAuthor {
    pub id: Uuid,
    pub content: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
}

#[derive(Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct CategoryName {
    pub name: String,
}

#[derive(Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct Category {
    pub name: String,
    pub id: Uuid,
}

#[derive(Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct PostCategories {
    pub post_id: Uuid,
    pub category_id: Uuid,
}

#[derive(Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct AuthorId {
    pub author_id: Uuid,
}

#[derive(Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct AuthorCommentId {
    pub author_id: Uuid,
}
