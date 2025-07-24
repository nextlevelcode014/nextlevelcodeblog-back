use std::{
    env::{self, var},
    sync::Arc,
};

use axum::{
    extract::Request,
    http::{
        header::{self, ACCEPT, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderName, HeaderValue, Method, StatusCode,
    },
    middleware::Next,
    response::IntoResponse,
    Extension,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::{
    app::AppState,
    domains::users::model::{User, UserRole},
    Error, Result,
};

use tracing::error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddeware {
    pub user: User,
}

pub async fn require_api_key(
    req: Request,
    next: Next,
) -> std::result::Result<axum::response::Response, StatusCode> {
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();
    let api_key_header = HeaderName::from_static("x-api-key");

    let Some(api_key_value) = headers.get(&api_key_header) else {
        return Err(Error::InternalServerError.status_code());
    };

    let Ok(api_key_str) = api_key_value.to_str() else {
        return Err(Error::InternalServerError.status_code());
    };

    let stored_key = match env::var("API_KEY") {
        Ok(key) => key,
        Err(_) => return Err(Error::InternalServerError.status_code()),
    };

    if api_key_str == stored_key {
        Ok(next.run(req).await)
    } else {
        Err(Error::InternalServerError.status_code())
    }
}

pub async fn auth(mut req: Request, next: Next) -> Result<impl IntoResponse> {
    let app_state = req
        .extensions()
        .get::<Arc<AppState>>()
        .ok_or(Error::Unauthorized)?;

    let cookies = CookieJar::from_headers(req.headers());

    let token = cookies
        .get("token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| auth_value.strip_prefix("Bearer ").map(|s| s.to_string()))
        })
        .ok_or(Error::Unauthorized)?;

    let token_details = app_state.users_service.decode_token(token)?;

    let user = if let Ok(user_id) = Uuid::parse_str(&token_details.sub) {
        app_state
            .users_service
            .get_user(Some(user_id), None, None, None, None)
            .await?
    } else {
        return Err(Error::Unauthorized);
    };

    req.extensions_mut().insert(JWTAuthMiddeware { user });

    Ok(next.run(req).await)
}

pub async fn role_check(
    Extension(_app_state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
    required_roles: Vec<UserRole>,
) -> Result<impl IntoResponse> {
    let user = req
        .extensions()
        .get::<JWTAuthMiddeware>()
        .ok_or_else(|| Error::Unauthorized)?;

    if !required_roles.contains(&user.user.role) {
        return Err(Error::Forbidden);
    }

    Ok(next.run(req).await)
}

pub fn configure_cors() -> Result<CorsLayer> {
    let x_api_key = HeaderName::from_static("x-api-key");
    let frontend_url = var("FRONT_URL").map_err(|e| {
        error!("Environment varible FRONT_URL must be set: {:?}", e);
        Error::InternalServerError
    })?;

    let origins = [frontend_url.parse::<HeaderValue>().map_err(|e| {
        error!("Error to parser header value: {:?}", e);
        Error::InternalServerError
    })?];

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE, ACCEPT, x_api_key])
        .allow_credentials(true)
        .expose_headers(vec![CONTENT_DISPOSITION])
        .max_age(std::time::Duration::from_secs(86400));

    Ok(cors)
}
