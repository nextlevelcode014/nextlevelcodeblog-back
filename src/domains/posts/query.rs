use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct PostCommentDto {
    pub id: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct UpdatePostCommentDto {
    pub content: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct CreateNewsPostDto {
    pub title: String,
    pub url: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNewsPost {
    pub title: Option<String>,
    pub url: Option<String>,
    pub description: Option<String>,
}

#[derive(Validate, Debug, sqlx::FromRow, Deserialize, Serialize)]
pub struct CategoryDto {
    #[validate(length(min = 2, max = 50, message = "Tag name is required"))]
    pub name: String,
}
