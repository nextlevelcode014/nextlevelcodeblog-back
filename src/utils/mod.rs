use crate::{config::Config, Error, Result};
use moka::future::Cache;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use time::Duration;
use tower_cookies::{cookie::SameSite, Cookie};
use tracing::{info, instrument};
use validator::Validate;

#[derive(Debug, Deserialize, Clone)]
pub struct Jwk {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

const JWKS_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

static JWKS_CACHE: Lazy<Cache<&'static str, Jwks>> = Lazy::new(|| {
    Cache::builder()
        .time_to_live(JWKS_TTL)
        .max_capacity(1)
        .build()
});

#[instrument(name = "fetch_google_jwks")]
pub async fn fetch_google_jwks() -> Result<Jwks> {
    if let Some(jwks) = JWKS_CACHE.get("jwks").await {
        info!("JWKS: cache hit");
        return Ok(jwks);
    }

    info!("JWKS: fetch remoto");
    let resp = Client::new()
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await
        .map_err(|_| Error::Unauthorized)?;

    let jwks = resp.json::<Jwks>().await.map_err(|_| Error::Unauthorized)?;

    JWKS_CACHE.insert("jwks", jwks.clone()).await;

    Ok(jwks)
}

pub fn validate_dto<T: Validate>(dto: &T) -> Result<()> {
    dto.validate().map_err(|validation_errors| {
        let mut errors = std::collections::HashMap::new();

        for (field, field_errors) in validation_errors.field_errors() {
            // Pega a primeira mensagem disponível, se existir
            if let Some(first_error) = field_errors
                .iter()
                .find_map(|error| error.message.as_ref())
            {
                errors.insert(field.to_string(), first_error.to_string());
            }
        }

        Error::validation(errors)
    })
}

pub fn create_auth_cookie(token: &str, config: &Config) -> Result<Cookie<'static>> {
    let cookie_duration = Duration::minutes(config.jwt_maxage * 60);

    let cookie = Cookie::build(("token", token.to_string()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .secure(config.is_production())
        .same_site(if config.is_production() {
            SameSite::None
        } else {
            SameSite::Lax
        })
        .build();

    Ok(cookie)
}

pub trait PipeExt<T> {
    fn pipe<U, F>(self, f: F) -> U
    where
        F: FnOnce(T) -> U;
}

impl<T> PipeExt<T> for T {
    fn pipe<U, F>(self, f: F) -> U
    where
        F: FnOnce(T) -> U,
    {
        f(self)
    }
}
