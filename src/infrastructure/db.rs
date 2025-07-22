use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresRepo {
    pool: PgPool,
}

impl PostgresRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
