use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::{
    domains::{
        posts::{model::Category, query::CategoryDto},
        private::repository::PrivateRepository,
        users::{
            model::{CreateUser, UserRole, UserRoleDto},
            query::DeleteUserDto,
            repository::UserRepository,
        },
    },
    infrastructure::db::PostgresRepo,
    Error, Result,
};

#[derive(Clone)]
pub struct PrivateService {
    repo: PostgresRepo,
}

impl PrivateService {
    #[instrument(name = "new_private_service", skip(repo))]
    pub fn new(repo: PostgresRepo) -> Self {
        Self { repo }
    }

    #[instrument(name = "get_users", skip(self))]
    pub async fn get_users(&self, admin_id: Uuid) -> Result<Vec<CreateUser>> {
        self.is_admin(admin_id).await?;
        let users = self.repo.get_users().await?;
        info!(count = users.len(), "Retrieved users");
        Ok(users)
    }

    #[instrument(name = "delete_user", skip(self, user_id))]
    pub async fn delete_user(&self, user_id: &DeleteUserDto, admin: Uuid) -> Result<()> {
        let user_id = Uuid::parse_str(&user_id.user_id).map_err(|_| {
            warn!(user_id = %user_id.user_id, "Invalid user ID format");
            Error::BadRequest {
                message: "Invalid ID format".to_string(),
            }
        })?;
        self.is_admin(admin).await?;
        info!(%user_id, "Deleting user");
        self.repo.delete_user(user_id).await?;
        info!(%user_id, "User deleted successfully");
        Ok(())
    }

    #[instrument(name = "create_category", skip(self, category))]
    pub async fn create_category(&self, category: &CategoryDto, admin_id: Uuid) -> Result<()> {
        info!(name = %category.name, "Creating category");
        self.is_admin(admin_id).await?;
        self.repo.create_category(&category.name).await?;
        info!(name = %category.name, "Category created successfully");
        Ok(())
    }

    #[instrument(name = "update_user_role", skip(self, user_role))]
    pub async fn update_user_role(&self, user_role: &UserRoleDto, admin_id: Uuid) -> Result<()> {
        let user_id = Uuid::parse_str(&user_role.user_id).map_err(|_| {
            warn!(user_id = %user_role.user_id, "Invalid user ID format");
            Error::BadRequest {
                message: "Invalid ID format".to_string(),
            }
        })?;
        self.is_admin(admin_id).await?;
        info!(%user_id, role = ?user_role.role, "Updating user role");
        self.repo.update_user_role(user_id, &user_role.role).await?;
        info!(%user_id, "User role updated successfully");
        Ok(())
    }

    #[instrument(name = "delete_category", skip(self))]
    pub async fn delete_category(&self, category_id: &str, admin_id: Uuid) -> Result<()> {
        let category_id = Uuid::parse_str(category_id).map_err(|_| {
            warn!(%category_id, "Invalid category ID format");
            Error::BadRequest {
                message: "Invalid ID format".to_string(),
            }
        })?;
        self.is_admin(admin_id).await?;
        info!(%category_id, "Deleting category");
        self.repo.delete_category(category_id).await?;
        info!(%category_id, "Category deleted successfully");
        Ok(())
    }

    #[instrument(name = "update_category", skip(self, category))]
    pub async fn update_category(
        &self,
        category: &CategoryDto,
        category_id: &str,
        admin_id: Uuid,
    ) -> Result<()> {
        let category_id = Uuid::parse_str(category_id).map_err(|_| {
            warn!(%category_id, "Invalid category ID format");
            Error::BadRequest {
                message: "Invalid ID format".to_string(),
            }
        })?;
        self.is_admin(admin_id).await?;
        info!(%category_id, name = %category.name, "Updating category");
        self.repo
            .update_category(&category.name, category_id)
            .await?;
        info!(%category_id, "Category updated successfully");
        Ok(())
    }

    #[instrument(name = "get_categories", skip(self))]
    pub async fn get_categories(&self, admin: Uuid) -> Result<Vec<Category>> {
        self.is_admin(admin).await?;
        let categories = self.repo.get_categories().await?;
        info!(count = categories.len(), "Retrieved categories");
        Ok(categories)
    }

    #[instrument(name = "is_admin", skip(self))]
    pub async fn is_admin(&self, admin_id: Uuid) -> Result<()> {
        let user = self
            .repo
            .get_user(Some(admin_id), None, None, None, None)
            .await?;

        let user = user.ok_or_else(|| {
            warn!("User not found");
            Error::NotFound
        })?;

        if user.role != UserRole::Admin {
            warn!(%admin_id, "User is not an admin!");
            return Err(Error::Forbidden);
        }

        Ok(())
    }
}
