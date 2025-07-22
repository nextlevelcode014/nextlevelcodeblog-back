use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, sqlx::Type, PartialEq)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, sqlx::Type, Clone)]
pub struct UserRoleDto {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: UserRole,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type, Default, Clone, PartialEq, Eq)]
#[sqlx(type_name = "auth_provider", rename_all = "lowercase")]
pub enum AuthProvider {
    #[default]
    Credentials,
    Google,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct User {
    pub id: uuid::Uuid,

    #[serde(rename = "authProvider")]
    pub auth_provider: AuthProvider,

    pub name: String,
    pub email: String,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,

    #[serde(rename = "passwordHash")]
    pub password_hash: Option<String>,
    #[serde(rename = "googleSub")]
    pub google_sub: Option<String>,

    pub picture: Option<String>,

    #[serde(rename = "verificationToken")]
    pub verification_token: Option<String>,
    #[serde(rename = "token_expiresat")]
    pub token_expires_at: Option<DateTime<Utc>>,

    pub role: UserRole,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub google_sub: Option<String>,
    pub email_verified: bool,
    pub picture: Option<String>,
    pub auth_provider: AuthProvider,
    pub verification_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
}
