use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    domains::users::model::{CreateUser, User},
    infrastructure::db::PostgresRepo,
    Result,
};

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_user(&self, new_user: &CreateUser) -> Result<User>;
    async fn add_verified_token(
        &self,
        user_id: Uuid,
        token_expires_at: DateTime<Utc>,
        token: &str,
    ) -> Result<()>;

    async fn verified_token(&self, token: &str) -> Result<()>;
}

#[async_trait]
impl AuthRepository for PostgresRepo {
    async fn create_user(&self, new_user: &CreateUser) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
        INSERT INTO users (
            name,
            email,
            password_hash,
            google_sub,
            picture,
            email_verified,
            verification_token,
            token_expires_at,
            auth_provider
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING 
            id,
            name,
            email,
            password_hash,
            google_sub,
            picture,
            email_verified,
            verification_token,
            token_expires_at,
            auth_provider,
            role,
            created_at,
            updated_at
        "#,
        )
        .bind(&new_user.name)
        .bind(&new_user.email)
        .bind(&new_user.password_hash)
        .bind(&new_user.google_sub)
        .bind(&new_user.picture)
        .bind(new_user.email_verified)
        .bind(&new_user.verification_token)
        .bind(new_user.token_expires_at)
        .bind(&new_user.auth_provider)
        .fetch_one(self.pool())
        .await?;

        Ok(user)
    }

    async fn add_verified_token(
        &self,
        user_id: Uuid,
        token_expires_at: DateTime<Utc>,
        token: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET verification_token = $1,
                token_expires_at = $2
            WHERE id = $3
            "#,
        )
        .bind(token)
        .bind(token_expires_at)
        .bind(user_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn verified_token(&self, token: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET email_verified = true,
                updated_at = Now(),
                verification_token = NULL,
                token_expires_at = NULL
            WHERE verification_token = $1
            "#,
        )
        .bind(token)
        .execute(self.pool())
        .await?;

        Ok(())
    }
}
