use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    domains::{
        private::repository::PrivateRepository,
        users::{
            model::{AuthProvider, User},
            query::{NameUpdateDto, UserPasswordUpdateDto},
            repository::UserRepository,
        },
    },
    infrastructure::db::PostgresRepo,
    validation_error, Error, Result,
};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[derive(Clone)]
pub struct UserService {
    repo: PostgresRepo,
    jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

impl UserService {
    #[instrument(name = "new_user_service", skip(repo, jwt_secret))]
    pub fn new(repo: PostgresRepo, jwt_secret: String) -> Self {
        Self { repo, jwt_secret }
    }

    #[instrument(name = "get_user", skip(self, name, email, token))]
    pub async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
        sub: Option<&str>,
    ) -> Result<User> {
        let user = self.repo.get_user(user_id, name, email, token, sub).await?;
        let user = user.ok_or_else(|| {
            warn!("User not found");
            Error::NotFound
        })?;
        info!(user_id = ?user.id, "User retrieved successfully");
        Ok(user)
    }

    #[instrument(name = "decode_token", skip(self, token))]
    pub fn decode_token<T: Into<String>>(&self, token: T) -> Result<Claims> {
        let token = token.into();

        let decode = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| {
            error!("Token decoding failed");
            Error::Unauthorized
        })?;

        Ok(decode.claims)
    }

    #[instrument(name = "delete_user", skip(self, user, password))]
    pub async fn delete_user(&self, user: &User, password: String) -> Result<()> {
        info!(%user.id, "Deleting user");

        if user.auth_provider != AuthProvider::Credentials {
            warn!("Invalid provider for delete user");
            return Err(Error::BadRequest {
                message: "Invalid provider".into(),
            });
        }

        let password_hash = user.password_hash.clone().ok_or_else(|| {
            warn!("Missing password hash while attempting to delete user");
            Error::BadRequest {
                message: "Password is required".into(),
            }
        })?;

        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&password_hash)?;

        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            warn!(user_id = %user.id, "Incorrect password while attempting to delete user");
            return Err(validation_error!("password", "Incorrect password!"));
        }
        self.repo.delete_user(user.id).await?;
        info!(%user.id, "User deleted successfully");
        Ok(())
    }

    #[instrument(name = "delete_google_user", skip(self, user))]
    pub async fn delete_google_user(&self, user: &User) -> Result<()> {
        info!(%user.id, "Deleting google user");

        if user.auth_provider != AuthProvider::Google {
            warn!("Invalid provider for delete google user");
            return Err(Error::BadRequest {
                message: "Invalid provider".into(),
            });
        }

        self.repo.delete_user(user.id).await?;
        info!(%user.id, "Google user deleted successfully");
        Ok(())
    }

    #[instrument(name = "update_username", skip(self, user, user_update))]
    pub async fn update_username(&self, user: &User, user_update: NameUpdateDto) -> Result<()> {
        if user_update.name == user.name {
            return Err(validation_error!(
                "name",
                "New username is the same as current one!"
            ));
        }

        let password_hash = user.password_hash.clone().ok_or_else(|| {
            warn!("Missing password hash while attempting to update username");
            Error::BadRequest {
                message: "Password is required".into(),
            }
        })?;

        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&password_hash)
            .map_err(|_| validation_error!("password", "Incorrect password!"))?;

        if argon2
            .verify_password(user_update.password.as_bytes(), &parsed_hash)
            .is_err()
        {
            warn!(user_id = %user.id, "Incorrect password while attempting to update username");
            return Err(validation_error!("password", "Incorrect password!"));
        }

        info!(user_id = %user.id, "Updating username");
        self.repo
            .update_username(user.id, &user_update.name)
            .await?;
        info!(user_id = %user.id, "Username updated successfully");

        Ok(())
    }

    #[instrument(name = "update_user_password", skip(self, user, user_update))]
    pub async fn update_user_password(
        &self,
        user: &User,
        user_update: UserPasswordUpdateDto,
    ) -> Result<()> {
        let password_hash = user.password_hash.clone().ok_or_else(|| {
            warn!("Password is required for login");
            Error::BadRequest {
                message: "Password is required".into(),
            }
        })?;

        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&password_hash)
            .map_err(|_| validation_error!("password", "Incorrect password!"))?;

        if argon2
            .verify_password(user_update.old_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            warn!(user_id = %user.id, "Incorrect password while attempting to update username");
            return Err(validation_error!("password", "Incorrect password!"));
        }

        if argon2
            .verify_password(user_update.new_password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            warn!("New password is the same as current password!");
            return Err(validation_error!(
                "password",
                "New password is the same as current password!"
            ));
        }

        let salt = SaltString::generate(&mut OsRng);
        let hash_password = argon2
            .hash_password(user_update.new_password.as_bytes(), &salt)?
            .to_string();

        info!(%user.id, "Updating user password");
        self.repo.update_password(user.id, &hash_password).await?;
        info!(%user.id, "User password updated successfully");

        Ok(())
    }
}
