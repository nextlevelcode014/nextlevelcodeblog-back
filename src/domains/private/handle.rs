use axum::{
    extract::Path,
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::{
    app::AppState,
    domains::{
        posts::query::CategoryDto,
        users::{
            model::{UserRole, UserRoleDto},
            query::DeleteUserDto,
        },
    },
    middleware::{role_check, JWTAuthMiddeware},
    Result,
};

pub fn private_routes() -> Router {
    let admin_routes = Router::new()
        .route("/users", get(get_users))
        .route("/delete-user", delete(delete_user))
        .route("/create-category", post(create_category))
        .route("/role", put(update_user_role))
        .route("/delete-category/{id}", delete(delete_category))
        .route("/update-category/{id}", put(update_category))
        .route("/categories", get(get_categories))
        .layer(middleware::from_fn(|state, req, next| {
            role_check(state, req, next, vec![UserRole::Admin])
        }));

    Router::new().nest("/admin", admin_routes)
}

#[instrument(name = "get_users", skip(app_state, jwt))]
pub async fn get_users(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse> {
    info!("Fetching all users");
    let users = app_state.private_service.get_users(jwt.user.id).await?;
    info!(count = users.len(), "Fetched all users");
    Ok((StatusCode::OK, Json(users)))
}

#[instrument(name = "delete_user", skip(app_state, user_id, jwt))]
pub async fn delete_user(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(user_id): Json<DeleteUserDto>,
) -> Result<impl IntoResponse> {
    info!(user_id = %user_id.user_id, "Deleting user");
    app_state
        .private_service
        .delete_user(&user_id, jwt.user.id)
        .await?;
    info!(user_id = %user_id.user_id, "User deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(name = "update_user_role", skip(app_state, jwt, role))]
pub async fn update_user_role(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(role): Json<UserRoleDto>,
) -> Result<impl IntoResponse> {
    info!(user_id = %role.user_id, "Updating user role");
    app_state
        .private_service
        .update_user_role(&role, jwt.user.id)
        .await?;
    info!(user_id = %role.user_id, "User role updated successfully");
    Ok(StatusCode::OK)
}

#[instrument(name = "create_category", skip(app_state, jwt, category))]
pub async fn create_category(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Json(category): Json<CategoryDto>,
) -> Result<impl IntoResponse> {
    info!(name = %category.name, "Creating category");
    app_state
        .private_service
        .create_category(&category, jwt.user.id)
        .await?;
    info!(name = %category.name, "Category created successfully");
    Ok(StatusCode::CREATED)
}

#[instrument(name = "delete_category", skip(app_state, jwt))]
pub async fn delete_category(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(category_id): Path<String>,
) -> Result<impl IntoResponse> {
    info!(%category_id, "Deleting category");
    app_state
        .private_service
        .delete_category(&category_id, jwt.user.id)
        .await?;
    info!(%category_id, "Category deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(name = "update_category", skip(app_state, jwt, category))]
pub async fn update_category(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
    Path(category_id): Path<String>,
    Json(category): Json<CategoryDto>,
) -> Result<impl IntoResponse> {
    info!(%category_id, "Updating category");
    app_state
        .private_service
        .update_category(&category, &category_id, jwt.user.id)
        .await?;
    info!(%category_id, "Category updated successfully");
    Ok(StatusCode::OK)
}

#[instrument(name = "get_categories", skip(app_state, jwt))]
pub async fn get_categories(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(jwt): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse> {
    info!("Fetching all categories");
    let categories = app_state
        .private_service
        .get_categories(jwt.user.id)
        .await?;
    info!(count = categories.len(), "Fetched all categories");
    Ok((StatusCode::OK, Json(categories)))
}
