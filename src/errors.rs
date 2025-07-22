use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};
use tracing::{error, warn};
use uuid::Uuid;

use crate::domains::auth::model::AuthResponse;

pub type Result<T> = core::result::Result<T, Error>;

/// Identificador único para rastreamento de erros
#[derive(Debug, Clone, Serialize)]
pub struct ErrorId(String);

impl ErrorId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for ErrorId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ErrorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Enum principal de erros da aplicação
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Resource not found")]
    NotFound,

    #[error("Unauthorized access")]
    Unauthorized,

    #[error("Internal server error")]
    InternalServerError,

    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("Database error: {source}")]
    DatabaseError {
        source: sqlx::Error,
        error_id: ErrorId,
    },

    #[error("Invalid hash format")]
    InvalidHashFormat {
        hash_error: argon2::password_hash::Error,
        error_id: ErrorId,
    },

    #[error("Forbidden access")]
    Forbidden,

    #[error("Resource conflict")]
    Conflict,

    #[error("Resource gone")]
    Gone,

    #[error("Unprocessable entity")]
    UnprocessableEntity,

    #[error("ReCaptcha validation failed")]
    RecaptchaValidation,

    #[error("Google login error")]
    GoogleLogin { response: AuthResponse },

    #[error("Validation error")]
    ValidationError {
        errors: HashMap<String, Vec<String>>,
    },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("JWT token error: {message}")]
    TokenError { message: String },

    #[error("Email service error: {message}")]
    EmailError { message: String },

    #[error("External service error: {service} - {message}")]
    ExternalServiceError {
        service: String,
        message: String,
        error_id: ErrorId,
    },
}

/// Resposta padronizada para erros de validação
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationResponse {
    pub code: u16,
    pub message: String,
    pub errors: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
}

/// Resposta padronizada para erros simples
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
    pub code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(status: &str, message: &str, code: u16) -> Self {
        Self {
            status: status.to_string(),
            message: message.to_string(),
            code,
            error_id: None,
            details: None,
        }
    }

    pub fn with_error_id(mut self, error_id: ErrorId) -> Self {
        self.error_id = Some(error_id.to_string());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap_or_default())
    }
}

impl Error {
    /// Cria um erro de BadRequest com uma mensagem
    pub fn bad_request<T: Into<String>>(message: T) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    /// Cria um erro de validação
    pub fn validation(errors: HashMap<String, Vec<String>>) -> Self {
        Self::ValidationError { errors }
    }

    /// Cria um erro de token JWT
    pub fn token_error<T: Into<String>>(message: T) -> Self {
        Self::TokenError {
            message: message.into(),
        }
    }

    /// Cria um erro de serviço de email
    pub fn email_error<T: Into<String>>(message: T) -> Self {
        Self::EmailError {
            message: message.into(),
        }
    }

    /// Cria um erro de serviço externo
    pub fn external_service_error<T: Into<String>, U: Into<String>>(
        service: T,
        message: U,
    ) -> Self {
        Self::ExternalServiceError {
            service: service.into(),
            message: message.into(),
            error_id: ErrorId::new(),
        }
    }

    /// Verifica se o erro é recuperável (cliente pode tentar novamente)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::ServiceUnavailable
                | Self::RateLimitExceeded
                | Self::InternalServerError
                | Self::DatabaseError { .. }
                | Self::ExternalServiceError { .. }
        )
    }

    /// Verifica se o erro é devido a um problema do cliente
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::BadRequest { .. }
                | Self::Unauthorized
                | Self::Forbidden
                | Self::NotFound
                | Self::Conflict
                | Self::Gone
                | Self::UnprocessableEntity
                | Self::ValidationError { .. }
                | Self::RecaptchaValidation
        )
    }

    /// Retorna o status code HTTP apropriado
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::ValidationError { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Gone => StatusCode::GONE,
            Self::UnprocessableEntity => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RecaptchaValidation => StatusCode::BAD_REQUEST,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::GoogleLogin { .. } => StatusCode::BAD_REQUEST,
            Self::TokenError { .. } => StatusCode::UNAUTHORIZED,
            Self::EmailError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ExternalServiceError { .. } => StatusCode::BAD_GATEWAY,
            Self::DatabaseError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidHashFormat { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = self.status_code();

        match self {
            Self::BadRequest { message } => {
                let response = ValidationResponse {
                    code: status_code.as_u16(),
                    message,
                    errors: None,
                    error_id: None,
                };
                (status_code, Json(response)).into_response()
            }

            Self::ValidationError { errors } => {
                let response = ValidationResponse {
                    code: status_code.as_u16(),
                    message: "Validation failed".to_string(),
                    errors: Some(errors),
                    error_id: None,
                };
                (status_code, Json(response)).into_response()
            }

            Self::GoogleLogin { response } => (status_code, Json(response)).into_response(),

            Self::DatabaseError { source, error_id } => {
                error!(error_id = %error_id, error = %source, "Database error occurred");
                let response = ErrorResponse::new(
                    "database_error",
                    "A database error occurred. Please try again later.",
                    status_code.as_u16(),
                )
                .with_error_id(error_id);
                (status_code, Json(response)).into_response()
            }

            Self::InvalidHashFormat {
                hash_error,
                error_id,
            } => {
                error!(error_id = %error_id, error = %hash_error, "Invalid hash format");
                let response = ErrorResponse::new(
                    "internal_error",
                    "An internal error occurred. Please try again later.",
                    status_code.as_u16(),
                )
                .with_error_id(error_id);
                (status_code, Json(response)).into_response()
            }

            Self::ExternalServiceError {
                service,
                message,
                error_id,
            } => {
                error!(
                    error_id = %error_id,
                    service = %service,
                    message = %message,
                    "External service error"
                );
                let response = ErrorResponse::new(
                    "external_service_error",
                    "External service is currently unavailable. Please try again later.",
                    status_code.as_u16(),
                )
                .with_error_id(error_id);
                (status_code, Json(response)).into_response()
            }

            Self::TokenError { message } => {
                warn!(message = %message, "Token error");
                let response = ErrorResponse::new(
                    "token_error",
                    "Invalid or expired token",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::EmailError { message } => {
                error!(message = %message, "Email service error");
                let response = ErrorResponse::new(
                    "email_error",
                    "Failed to send email. Please try again later.",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::RateLimitExceeded => {
                warn!("Rate limit exceeded");
                let response = ErrorResponse::new(
                    "rate_limit_exceeded",
                    "Too many requests. Please try again later.",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::ServiceUnavailable => {
                error!("Service unavailable");
                let response = ErrorResponse::new(
                    "service_unavailable",
                    "Service is temporarily unavailable. Please try again later.",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            // Erros simples sem corpo de resposta detalhado
            Self::NotFound => {
                let response =
                    ErrorResponse::new("not_found", "Resource not found", status_code.as_u16());
                (status_code, Json(response)).into_response()
            }

            Self::Unauthorized => {
                let response = ErrorResponse::new(
                    "unauthorized",
                    "Authentication required",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::Forbidden => {
                let response =
                    ErrorResponse::new("forbidden", "Access denied", status_code.as_u16());
                (status_code, Json(response)).into_response()
            }

            Self::Conflict => {
                let response =
                    ErrorResponse::new("conflict", "Resource conflict", status_code.as_u16());
                (status_code, Json(response)).into_response()
            }

            Self::Gone => {
                let response = ErrorResponse::new(
                    "gone",
                    "Resource no longer available",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::UnprocessableEntity => {
                let response = ErrorResponse::new(
                    "unprocessable_entity",
                    "Unable to process the request",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::RecaptchaValidation => {
                let response = ErrorResponse::new(
                    "recaptcha_validation_failed",
                    "ReCaptcha validation failed",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }

            Self::InternalServerError => {
                error!("Internal server error occurred");
                let response = ErrorResponse::new(
                    "internal_server_error",
                    "An internal error occurred. Please try again later.",
                    status_code.as_u16(),
                );
                (status_code, Json(response)).into_response()
            }
        }
    }
}

// Implementações automáticas de From para conversões específicas
impl From<sqlx::Error> for Error {
    fn from(source: sqlx::Error) -> Self {
        let error_id = ErrorId::new();
        error!(error_id = %error_id, error = %source, "Database error occurred");

        Self::DatabaseError { source, error_id }
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from(hash_error: argon2::password_hash::Error) -> Self {
        let error_id = ErrorId::new();
        error!(error_id = %error_id, error = %hash_error, "Invalid hash format");

        Self::InvalidHashFormat {
            hash_error,
            error_id,
        }
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(source: jsonwebtoken::errors::Error) -> Self {
        Self::token_error(format!("JWT error: {}", source))
    }
}

impl From<reqwest::Error> for Error {
    fn from(source: reqwest::Error) -> Self {
        Self::external_service_error("HTTP Client", source.to_string())
    }
}

// Helper macros para criar erros de validação facilmente
#[macro_export]
macro_rules! validation_error {
    ($field:expr, $message:expr) => {{
        let mut errors = std::collections::HashMap::new();
        errors.insert($field.to_string(), vec![$message.to_string()]);
        $crate::Error::validation(errors)
    }};

    ($($field:expr => $message:expr),+ $(,)?) => {{
        let mut errors = std::collections::HashMap::new();
        $(
            errors.insert($field.to_string(), vec![$message.to_string()]);
        )+
        $crate::Error::validation(errors)
    }};
}

// Trait para adicionar contexto aos erros
pub trait ErrorContext<T> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T> ErrorContext<T> for Result<T> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|_| Error::bad_request(f()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_id_generation() {
        let id1 = ErrorId::new();
        let id2 = ErrorId::new();
        assert_ne!(id1.to_string(), id2.to_string());
    }

    #[test]
    fn test_error_classification() {
        assert!(Error::ServiceUnavailable.is_recoverable());
        assert!(Error::Unauthorized.is_client_error());
        assert!(!Error::Unauthorized.is_recoverable());
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(Error::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(Error::Unauthorized.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            Error::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
