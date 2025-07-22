use std::{env::var, sync::Arc};

use axum::{middleware as axum_middleware, Extension, Router};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::{
    config::Config,
    domains::{
        auth::{handle::auth_houtes, service::AuthService},
        posts::{handle::news_post_routes, service::NewsPostsService},
        private::{handle::private_routes, service::PrivateService},
        recaptcha::service::RecaptchaService,
        users::{handle::users_houtes, service::UserService},
    },
    infrastructure::db::PostgresRepo,
    middleware::{auth, configure_cors, require_api_key},
};

use tracing::error;

#[derive(Clone)]
pub struct AppState {
    pub api_key: String,
    pub db_pool: PgPool,
    pub config: Config,
    pub auth_service: AuthService,
    pub news_post_service: NewsPostsService,
    pub users_service: UserService,
    pub private_service: PrivateService,
    pub recaptcha_service: RecaptchaService,
}

pub fn create_routes(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
        .nest(
            "/private",
            private_routes()
                .layer(axum_middleware::from_fn(auth))
                .layer(axum_middleware::from_fn(require_api_key)),
        )
        .nest("/auth", auth_houtes())
        .nest(
            "/users",
            users_houtes().layer(axum_middleware::from_fn(auth)),
        )
        .nest(
            "/posts",
            news_post_routes().layer(axum_middleware::from_fn(auth)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}

pub async fn build_app_state(config: Config, db_pool: PgPool) -> Arc<AppState> {
    let api_key = var("API_KEY").unwrap_or_else(|_| {
        panic!("API_KEY environment variable must be set and non-empty!");
    });

    let db_blog = PostgresRepo::new(db_pool.clone());

    Arc::new(AppState {
        api_key,
        db_pool,
        config: config.clone(),
        auth_service: AuthService::with_default_config(db_blog.clone()),
        news_post_service: NewsPostsService::new(db_blog.clone()),
        users_service: UserService::new(db_blog.clone(), config.jwt_secret.clone()),
        private_service: PrivateService::new(db_blog.clone()),
        recaptcha_service: RecaptchaService::new(),
    })
}

pub fn build_app(app_state: Arc<AppState>) -> Router {
    let cors = configure_cors().unwrap_or_else(|e| {
        error!("{:?}", e);
        std::process::exit(1);
    });
    create_routes(app_state.clone())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
