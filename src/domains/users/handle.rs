use std::sync::Arc;

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Extension, Json, Router,
};
use tracing::{info, instrument};
use validator::Validate;

use crate::{
    app::AppState,
    domains::{
        auth::query::{Response, UserResponseDto},
        users::query::{FilterUserDto, NameUpdateDto, UserData, UserPasswordUpdateDto},
    },
    middleware::JWTAuthMiddeware,
    utils::validate_dto,
    Error, Result,
};

pub fn users_houtes() -> Router {
    Router::new()
        .route("/me", get(get_me))
        .route("/delete/{id}", delete(delete_user))
        .route("/update-username", put(update_user_name))
        .route("/update-password", put(update_user_password))
}

#[instrument(name = "get_me", skip(_app_state, user))]
pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse> {
    info!(user_id = %user.user.id, "Fetching current user");
    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    info!(user_id = %user.user.id, "Fetched user successfully");
    Ok((StatusCode::OK, Json(response_data)))
}

#[tracing::instrument(name = "delete_user", skip(app_state))]
pub async fn delete_user(
    Extension(app_state): Extension<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse> {
    info!(user_id = %user_id, "Deleting current user");
    app_state.users_service.delete_user(&user_id).await?;

    let response = Response {
        message: "User deleted Successfully".to_string(),
        status: "success",
    };

    info!(user_id = %user_id, "Deleted user successfully");
    Ok((StatusCode::NO_CONTENT, Json(response)))
}

#[instrument(name = "update_user_name", skip(app_state, jwt, user_update))]
pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(user_update): Json<NameUpdateDto>,
) -> Result<impl IntoResponse> {
    info!(user_id = %jwt.user.id, "Updating username");

    validate_dto(&user_update)?;

    app_state
        .users_service
        .update_username(&jwt.user, user_update)
        .await?;

    let response = Response {
        message: "Username updated Successfully".to_string(),
        status: "success",
    };

    info!(user_id = %jwt.user.id, "Username updated successfully");
    Ok((StatusCode::OK, Json(response)))
}

#[instrument(name = "update_user_password", skip(app_state, jwt, user_update))]
pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(user_update): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse> {
    info!(user_id = %jwt.user.id, "Updating password");
    user_update.validate().map_err(|_| Error::BadRequest {
        message: "Invalid data".to_string(),
    })?;

    app_state
        .users_service
        .update_user_password(&jwt.user, user_update)
        .await?;

    let response = Response {
        message: "Password updated Successfully".to_string(),
        status: "success",
    };

    info!(user_id = %jwt.user.id, "Password updated successfully");
    Ok((StatusCode::OK, Json(response)))
}
