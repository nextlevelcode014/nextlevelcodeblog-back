use backend_nextlevelcodeblog::{
    app::{build_app, build_app_state},
    config::{init_logger, Config},
    tasks::spawn_tasks,
};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    init_logger();
    dotenv().ok();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            info!("Connection to the database is successful!");
            pool
        }
        Err(err) => {
            error!("Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    info!("Running database migrations...");
    sqlx::migrate!().run(&pool).await.unwrap();

    let app_state = build_app_state(config, pool).await;

    spawn_tasks(app_state.clone()).await;

    let app = build_app(app_state.clone());

    let listener = tokio::net::TcpListener::bind(format!(
        "[::]:{}",
        env::var("PORT").unwrap_or_else(|_| "8080".to_string())
    ))
    .await
    .unwrap();
    info!("{} - {:?}", "LISTENING", listener.local_addr());
    axum::serve(listener, app).await.unwrap();
}
