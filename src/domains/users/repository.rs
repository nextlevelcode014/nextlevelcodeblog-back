use async_trait::async_trait;
use uuid::Uuid;

use crate::{domains::users::model::User, infrastructure::db::PostgresRepo, Error, Result};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
        google_sub: Option<&str>,
    ) -> Result<Option<User>>;
    async fn update_password(&self, user_id: Uuid, new_password: &str) -> Result<()>;
    async fn update_username(&self, user_id: Uuid, new_username: &str) -> Result<()>;
}

#[async_trait]
impl UserRepository for PostgresRepo {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
        google_sub: Option<&str>,
    ) -> Result<Option<User>> {
        let mut user: Option<User> = None;

        if let Some(user_id) = user_id {
            user = sqlx::query_as::<_, User>(
                r#"SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role FROM users WHERE id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(self.pool()).await?;
        } else if let Some(name) = name {
            user = sqlx::query_as::<_, User>(
                r#"SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role FROM users WHERE name = $1"#,
            )
            .bind(name)
            .fetch_optional(self.pool()).await?;
        } else if let Some(email) = email {
            user = sqlx::query_as::<_, User>(
                r#"SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role FROM users WHERE email = $1"#,
            )
            .bind(email)
            .fetch_optional(self.pool()).await?;
        } else if let Some(token) = token {
            user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role
                FROM users
                WHERE verification_token = $1"#,
            )
            .bind(token)
            .fetch_optional(self.pool())
            .await?;
        } else if let Some(sub) = google_sub {
            user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role
                FROM users
                WHERE google_sub = $1"#,
            )
            .bind(sub)
            .fetch_optional(self.pool())
            .await?;
        }

        Ok(user)
    }

    async fn update_password(&self, user_id: Uuid, new_password: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, token_expires_at = NULL
            WHERE id = $2
            "#,
        )
        .bind(new_password)
        .bind(user_id)
        .execute(self.pool())
        .await
        .map_err(|e| Error::external_service_error("db", e.to_string()))?;

        Ok(())
    }
    async fn update_username(&self, user_id: Uuid, new_username: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET name = $1
            WHERE id = $2
            "#,
        )
        .bind(new_username)
        .bind(user_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }
}
