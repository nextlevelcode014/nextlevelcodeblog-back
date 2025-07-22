use backend_nextlevelcodeblog::domains::users::model::{CreateUser, User, UserRole};
use sqlx::PgPool;

pub async fn create_user_test(
    pg_pool: &PgPool,
    new_user: &CreateUser,
    role: UserRole,
) -> Result<User, sqlx::Error> {
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
            auth_provider,
            role
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
    .bind(role)
    .fetch_one(pg_pool)
    .await?;

    Ok(user)
}
