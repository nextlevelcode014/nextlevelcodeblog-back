use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct PostWithCommentRow {
    pub post_id: Uuid,
    pub url: String,
    pub title: String,
    pub description: String,
    pub author_id: Uuid, // novo campo
    pub post_author_name: String,
    pub post_created_at: DateTime<Utc>,

    pub comment_author_id: Option<Uuid>,
    pub comment_id: Option<Uuid>,
    pub comment_content: Option<String>,
    pub comment_author_name: Option<String>,
    pub comment_created_at: Option<DateTime<Utc>>,
}

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
pub struct NewsPostWithComments {
    pub id: Uuid,
    pub url: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
    pub author_name: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub comments: Vec<PostCommentWithAuthor>,
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
    #[serde(rename = "authorName")]
    pub author_name: String,
    #[serde(rename = "authorId")]
    pub author_id: Uuid,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
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
