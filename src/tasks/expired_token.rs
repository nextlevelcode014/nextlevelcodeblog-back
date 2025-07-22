use std::{sync::Arc, time::Duration};

use tokio::time::interval;
use tracing::{error, info};

use crate::{app::AppState, Result};

pub async fn run(app_state: Arc<AppState>) {
    let mut interval = interval(Duration::from_secs(60 * 60 * 24 * 7));
    loop {
        interval.tick().await;
        if let Err(e) = task_stale_unverified_user(&app_state).await {
            error!("Cleanup tasks failed {:?}", e);
        }
    }
}

async fn task_stale_unverified_user(app_state: &AppState) -> Result<()> {
    info!("Starting task to delete stale unverified users...");
    sqlx::query(
        r#"
            DELETE FROM users
            WHERE email_verified = false AND created_at < NOW() - INTERVAL '7 days'
            "#,
    )
    .execute(&app_state.db_pool)
    .await?;

    Ok(())
}
