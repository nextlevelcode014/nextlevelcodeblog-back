use std::env;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::Client;
use serde::Serialize;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    domains::{
        auth::{
            model::{GoogleUserInfo, GoogleUserInfoClaims, GoogleUserInfoReturn},
            query::RegisterUserDto,
            repository::AuthRepository,
        },
        users::{
            model::{AuthProvider, CreateUser, User},
            repository::UserRepository,
            service::Claims,
        },
    },
    infrastructure::{
        db::PostgresRepo,
        mail::mails::{send_forgot_password_email, send_welcome_email},
    },
    utils::fetch_google_jwks,
    Error, PipeExt, Result,
};

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    pub google_client_id: String,
    pub frontend_url: String,
    pub verification_token_expiry_hours: i64,
    pub reset_token_expiry_minutes: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set"),
            jwt_expiration: env::var("JWT_MAXAGE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("JWT_MAXAGE must be a valid number"),
            google_client_id: env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
            frontend_url: env::var("FRONT_URL").expect("FRONT_URL must be set"),
            verification_token_expiry_hours: 24,
            reset_token_expiry_minutes: 30,
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    repo: PostgresRepo,
    config: AuthConfig,
    http_client: Client,
}

#[derive(Debug, Serialize)]
pub struct LoginResult {
    pub token: String,
    pub user_id: String,
    pub expires_at: i64,
}

impl AuthService {
    pub fn new(repo: PostgresRepo, config: AuthConfig) -> Self {
        Self {
            repo,
            config,
            http_client: Client::new(),
        }
    }

    pub fn with_default_config(repo: PostgresRepo) -> Self {
        Self::new(repo, AuthConfig::default())
    }

    #[instrument(name = "auth_register", skip(self, new_user), fields(email = %new_user.email))]
    pub async fn register(&self, new_user: RegisterUserDto) -> Result<User> {
        info!("Registering user");

        if self.email_exists(&new_user.email).await? {
            warn!("Email already registered");
            return Err(Error::Conflict);
        }

        let create_user_data = match new_user.auth_provider {
            AuthProvider::Credentials => self.prepare_credentials_user(new_user).await?,
            AuthProvider::Google => self.prepare_google_user(new_user).await?,
        };

        let user = self.repo.create_user(&create_user_data).await?;

        info!(user_id = %user.id, "User registered successfully");
        Ok(user)
    }

    #[instrument(name = "auth_login", skip(self, password), fields(email = %email))]
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        auth_provider: AuthProvider,
    ) -> Result<LoginResult> {
        info!("Attempting login");

        let user = self.get_user_by_email(email).await?;

        self.validate_user_for_login(&user, auth_provider)?;
        self.verify_password(&user, password)?;

        info!(user_id = %user.id, "Login successful");

        let token = self.generate_token(&user.id.to_string(), self.config.jwt_expiration)?;
        let expires_at = (Utc::now() + Duration::minutes(self.config.jwt_expiration)).timestamp();

        Ok(LoginResult {
            token,
            user_id: user.id.to_string(),
            expires_at,
        })
    }

    #[instrument(name = "auth_verify_email", skip(self), fields(token = %token))]
    pub async fn verify_email(&self, token: String) -> Result<String> {
        info!("Verifying email");

        let user = self.get_user_by_token(&token).await?;

        if user.email_verified {
            info!(user_id = %user.id, "Email already verified");
            return Err(Error::Conflict);
        }

        if user.auth_provider != AuthProvider::Credentials {
            warn!("Invalid provider for email verification");
            return Err(Error::BadRequest {
                message: "Invalid provider".into(),
            });
        }

        self.validate_token_expiry(&user)?;

        self.repo.verified_token(&token).await?;

        send_welcome_email(&user.email, &user.name).await?;

        info!(user_id = %user.id, "Email verified successfully");
        self.generate_token(&user.id.to_string(), self.config.jwt_expiration)
    }

    #[instrument(name = "auth_forgot_password", skip(self), fields(email = %email))]
    pub async fn forgot_password(&self, email: String) -> Result<()> {
        info!("Processing password reset request");

        let user = self.get_user_by_email(&email).await?;

        if user.auth_provider != AuthProvider::Credentials {
            warn!("Invalid provider for password reset");
            return Err(Error::BadRequest {
                message: "Invalid provider".into(),
            });
        }

        let verification_token = self.generate_secure_token();
        let expires_at = Utc::now() + Duration::minutes(self.config.reset_token_expiry_minutes);

        self.repo
            .add_verified_token(user.id, expires_at, &verification_token)
            .await?;

        let reset_link = format!(
            "{}/confirm-auth/reset-password?token={}",
            self.config.frontend_url, verification_token
        );

        send_forgot_password_email(&user.email, &reset_link, &user.name)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to send password reset email");
                Error::EmailError {
                    message: "Failed to send password reset email".into(),
                }
            })?;

        info!("Password reset email sent successfully");
        Ok(())
    }

    #[instrument(name = "auth_reset_password", skip(self, new_password), fields(token = %token))]
    pub async fn reset_password(&self, token: String, new_password: String) -> Result<()> {
        info!("Resetting password");

        let user = self.get_user_by_token(&token).await?;

        if user.auth_provider != AuthProvider::Credentials {
            warn!("Invalid provider for password reset");
            return Err(Error::BadRequest {
                message: "Invalid provider".into(),
            });
        }

        self.validate_token_expiry(&user)?;

        let password_hash = self.hash_password(&new_password)?;

        self.repo.update_password(user.id, &password_hash).await?;
        self.repo.verified_token(&token).await?;

        info!(user_id = %user.id, "Password reset successfully");
        Ok(())
    }

    #[instrument(name = "handle_google_login", skip(self, token))]
    pub async fn handle_google_login(&self, token: &str) -> Result<GoogleUserInfoReturn> {
        debug!("Processing Google login");

        let user_info = self.get_google_user_info(token).await?;
        let existing_user = self
            .repo
            .get_user(None, None, Some(&user_info.email), None, None)
            .await?;

        match existing_user {
            None => {
                debug!("Creating new Google user");
                self.create_google_user(&user_info).await?;
            }
            Some(user) => {
                if user.auth_provider == AuthProvider::Credentials {
                    warn!("Email already registered with credentials provider");
                    return Err(Error::Conflict);
                }
                debug!(user_id = %user.id, "Existing Google user found");
            }
        }

        let claims = self.verify_google_token_jwks(token).await?;
        let jwt_token = self.generate_token(&claims.sub, self.config.jwt_expiration)?;

        Ok(GoogleUserInfoReturn {
            email: user_info.email,
            name: user_info.name,
            token: jwt_token,
        })
    }

    #[instrument(name = "verify_google_token_jwks", skip_all)]
    pub async fn verify_google_token_jwks(&self, token: &str) -> Result<GoogleUserInfoClaims> {
        debug!("Verifying Google token with JWKS");

        let header = decode_header(token).map_err(|e| {
            error!(error = %e, "Failed to decode token header");
            Error::Unauthorized
        })?;

        let kid = header.kid.ok_or_else(|| {
            error!("Missing kid in token header");
            Error::Unauthorized
        })?;

        let jwks = fetch_google_jwks().await?;
        let jwk = jwks.find(&kid).ok_or_else(|| {
            error!(kid = %kid, "JWK not found for kid");
            Error::Unauthorized
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            error!(error = %e, "Failed to create decoding key");
            Error::Unauthorized
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.google_client_id]);
        validation.set_issuer(&["https://accounts.google.com"]);

        let token_data = decode::<GoogleUserInfoClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                error!(error = %e, "Failed to decode and verify token");
                Error::Unauthorized
            })?;

        debug!("Google token verified successfully");
        Ok(token_data.claims)
    }

    // Métodos auxiliares privados

    async fn email_exists(&self, email: &str) -> Result<bool> {
        Ok(self
            .repo
            .get_user(None, None, Some(email), None, None)
            .await?
            .is_some())
    }

    async fn prepare_credentials_user(&self, new_user: RegisterUserDto) -> Result<CreateUser> {
        let password = new_user.password_hash.ok_or_else(|| Error::BadRequest {
            message: "Password is required".into(),
        })?;

        let password_hash = self.hash_password(&password)?;
        let verification_token = self.generate_secure_token();
        let token_expires_at =
            Utc::now() + Duration::hours(self.config.verification_token_expiry_hours);

        Ok(CreateUser {
            auth_provider: AuthProvider::Credentials,
            email: new_user.email,
            email_verified: false,
            google_sub: None,
            name: new_user.name,
            password_hash: Some(password_hash),
            picture: None,
            token_expires_at: Some(token_expires_at),
            verification_token: Some(verification_token),
        })
    }

    async fn prepare_google_user(&self, new_user: RegisterUserDto) -> Result<CreateUser> {
        let google_sub = new_user.google_sub.ok_or_else(|| Error::BadRequest {
            message: "Google sub is required".into(),
        })?;

        Ok(CreateUser {
            auth_provider: AuthProvider::Google,
            email: new_user.email,
            email_verified: new_user.email_verified,
            google_sub: Some(google_sub),
            name: new_user.name,
            password_hash: None,
            picture: new_user.picture,
            token_expires_at: None,
            verification_token: None,
        })
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User> {
        self.repo
            .get_user(None, None, Some(email), None, None)
            .await?
            .ok_or_else(|| {
                info!("User not found for email");
                Error::NotFound
            })
    }

    async fn get_user_by_token(&self, token: &str) -> Result<User> {
        self.repo
            .get_user(None, None, None, Some(token), None)
            .await?
            .ok_or_else(|| {
                warn!("User not found for token");
                Error::NotFound
            })
    }

    fn validate_user_for_login(&self, user: &User, auth_provider: AuthProvider) -> Result<()> {
        if !user.email_verified {
            info!(user_id = %user.id, "User not verified");
            return Err(Error::Unauthorized);
        }

        if user.auth_provider != auth_provider {
            info!("Authentication provider mismatch");
            return Err(Error::Conflict);
        }

        Ok(())
    }

    fn verify_password(&self, user: &User, password: &str) -> Result<()> {
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| Error::BadRequest {
                message: "Password is required".into(),
            })?;

        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(password_hash).map_err(|e| {
            error!(error = %e, "Failed to parse password hash");
            Error::InternalServerError
        })?;

        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| {
                info!(user_id = %user.id, "Invalid password");
                Error::Unauthorized
            })
    }

    fn validate_token_expiry(&self, user: &User) -> Result<()> {
        if let Some(expires_at) = user.token_expires_at {
            if expires_at < Utc::now() {
                info!(user_id = %user.id, "Token expired");
                return Err(Error::Gone);
            }
        }
        Ok(())
    }

    fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                error!(error = %e, "Failed to hash password");
                Error::InternalServerError
            })?
            .to_string()
            .pipe(Ok)
    }

    fn generate_secure_token(&self) -> String {
        Uuid::now_v7().to_string()
    }

    async fn get_google_user_info(&self, token: &str) -> Result<GoogleUserInfo> {
        let url = format!("https://oauth2.googleapis.com/tokeninfo?id_token={}", token);

        let response = self.http_client.get(&url).send().await.map_err(|e| {
            error!(error = %e, "Failed to call Google tokeninfo API");
            Error::Unauthorized
        })?;

        if !response.status().is_success() {
            error!(status = %response.status(), "Google tokeninfo API returned error");
            return Err(Error::Unauthorized);
        }

        response.json::<GoogleUserInfo>().await.map_err(|e| {
            error!(error = %e, "Failed to parse Google user info");
            Error::Unauthorized
        })
    }

    async fn create_google_user(&self, user_info: &GoogleUserInfo) -> Result<User> {
        let create_user = CreateUser {
            name: user_info.name.clone(),
            email: user_info.email.clone(),
            password_hash: None,
            google_sub: Some(user_info.sub.clone()),
            picture: user_info.picture.clone(),
            email_verified: user_info.email_verified,
            auth_provider: AuthProvider::Google,
            token_expires_at: None,
            verification_token: None,
        };

        self.repo.create_user(&create_user).await
    }

    pub fn generate_token(&self, user_id: &str, expires_in_minutes: i64) -> Result<String> {
        let now = Utc::now();
        let exp = (now + Duration::minutes(expires_in_minutes)).timestamp() as usize;
        let iat = now.timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            iat,
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| {
            error!(error = %e, "Failed to encode JWT token");
            Error::InternalServerError
        })
    }
}
