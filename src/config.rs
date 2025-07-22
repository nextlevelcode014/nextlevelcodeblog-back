use std::env::var;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_maxage: i64,
    pub port: u16,
    pub api_env: String,
    pub google_client_id: String,
}

impl Config {
    pub fn init() -> Config {
        let database_url = var("DATABASE_URL").expect("DATABASE_URL must be set");
        //.replace("postgres://", "postgresql://")
        //+ "&prepare=false";
        let jwt_secret = var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set");
        let jwt_maxage = var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");
        let port = var("PORT").expect("PORT must be set");
        let api_env: String = var("API_ENV").expect("API_ENV must be set");
        let google_client_id = var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set");

        Config {
            database_url,
            jwt_secret,
            jwt_maxage: jwt_maxage.parse::<i64>().unwrap(),
            port: port.parse::<u16>().unwrap(),
            api_env,
            google_client_id,
        }
    }

    pub fn is_production(&self) -> bool {
        self.api_env == "production"
    }
}
pub fn init_logger() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();
}
