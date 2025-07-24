use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::domains::users::model::{AuthProvider, User, UserRole};

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct UserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: UserRole,
    pub verified: bool,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct DeleteUserDto {
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: String,

    #[serde(rename = "authProvider")]
    pub auth_provider: AuthProvider,

    pub name: String,
    pub email: String,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,

    #[serde(rename = "googleSub")]
    pub google_sub: Option<String>,

    pub picture: Option<String>,

    pub role: String,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            email_verified: user.email_verified,
            role: user.role.to_str().to_string(),
            created_at: user.created_at,
            updated_at: user.updated_at,
            auth_provider: user.auth_provider.to_owned(),
            google_sub: user.google_sub.to_owned(),
            picture: user.picture.to_owned(),
        }
    }

    pub fn _filter_users(user: &[User]) -> Vec<FilterUserDto> {
        user.iter().map(FilterUserDto::filter_user).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateDto {
    #[validate(length(min = 8, message = "new password must be at least 8 characters"))]
    #[serde(rename = "newPassword")]
    pub new_password: String,

    #[validate(
        length(
            min = 8,
            message = "new password confirm must be at least 8 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    #[serde(rename = "newPasswordConfirm")]
    pub new_password_confirm: String,

    #[validate(length(min = 8, message = "Old password must be at least 8 characters"))]
    #[serde(rename = "oldPassword")]
    pub old_password: String,
}
#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct NameUpdateDto {
    #[validate(length(min = 3, max = 50, message = "Name is required"))]
    pub name: String,
    #[validate(length(min = 8, max = 128, message = "Password is required"))]
    pub password: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct DeleteUser {
    pub password: String,
}
