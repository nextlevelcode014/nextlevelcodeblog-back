use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domains::users::{model::AuthProvider, query::UserData};

#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(
        length(min = 3, max = 50, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[serde(rename = "password")]
    pub password_hash: String,
    #[serde(rename = "recaptchaToken")]
    pub recaptcha_token: String,
    #[serde(rename = "authProvider")]
    pub auth_provider: AuthProvider,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterUserDto {
    #[validate(length(
        min = 3,
        max = 50,
        message = "Name must be between 3 and 50 characters"
    ))]
    pub name: String,

    #[validate(
        length(
            min = 3,
            max = 255,
            message = "Email must be between 3 and 255 characters"
        ),
        email(message = "Invalid email address")
    )]
    pub email: String,

    /// Optional for external providers (e.g., Google)
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[serde(rename = "password", skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,

    /// Only used for password-based registrations
    #[validate(length(min = 8, message = "Confirm Password is required"))]
    #[serde(rename = "passwordConfirm", skip_serializing_if = "Option::is_none")]
    pub password_hash_confirm: Option<String>,

    #[serde(rename = "recaptchaToken")]
    pub recaptcha_token: String,

    /// Optional: only for Google registration
    #[serde(rename = "googleSub", skip_serializing_if = "Option::is_none")]
    pub google_sub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Optional for OAuth flows (Google may verify it)
    #[serde(rename = "emailVerified", default)]
    pub email_verified: bool,

    #[serde(rename = "authProvider")]
    pub auth_provider: AuthProvider,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub token: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 3, max = 50, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct ResetPasswordRequestDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,

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
    #[serde(rename = "confirmPassword")]
    pub new_password_confirm: String,
}
