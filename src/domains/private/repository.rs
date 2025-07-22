use crate::{
    domains::{
        posts::model::Category,
        users::model::{CreateUser, UserRole},
    },
    infrastructure::db::PostgresRepo,
    Result,
};
use async_trait::async_trait;
use sqlx::{query, query_as};
use uuid::Uuid;

#[async_trait]
pub trait PrivateRepository: Sync + Send {
    async fn get_users(&self) -> Result<Vec<CreateUser>>;
    async fn delete_user(&self, user_id: Uuid) -> Result<()>;
    async fn create_category(&self, category_name: &str) -> Result<()>;
    async fn update_user_role(&self, user_id: Uuid, role: &UserRole) -> Result<()>;
    async fn delete_category(&self, category_id: Uuid) -> Result<()>;
    async fn update_category(&self, category_name: &str, category_id: Uuid) -> Result<()>;
    async fn get_categories(&self) -> Result<Vec<Category>>;
}

#[async_trait]
impl PrivateRepository for PostgresRepo {
    async fn get_users(&self) -> Result<Vec<CreateUser>> {
        let users = query_as::<_, CreateUser>(
            r#"
            SELECT id, google_sub, name, email, password_hash, email_verified, auth_provider, picture, created_at, updated_at, verification_token, token_expires_at, role FROM users
            "#,
        )
        .fetch_all(self.pool())
        .await?;

        Ok(users)
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<()> {
        query(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn create_category(&self, category_name: &str) -> Result<()> {
        query(
            r#"
            INSERT INTO categories (name)
            VALUES ($1)
            "#,
        )
        .bind(category_name)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn update_user_role(&self, user_id: Uuid, role: &UserRole) -> Result<()> {
        query(
            r#"
            UPDATE users
            SET role = $2
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(role)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn delete_category(&self, category_id: Uuid) -> Result<()> {
        query(
            r#"
            DELETE FROM categories
            WHERE id = $1
            "#,
        )
        .bind(category_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn update_category(&self, category_name: &str, category_id: Uuid) -> Result<()> {
        query(
            r#"
            UPDATE categories
            SET name = $2
            WHERE id = $1"#,
        )
        .bind(category_id)
        .bind(category_name)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn get_categories(&self) -> Result<Vec<Category>> {
        let categories = query_as::<_, Category>(
            r#"
            SELECT * FROM categories
            "#,
        )
        .fetch_all(self.pool())
        .await?;

        Ok(categories)
    }
}
