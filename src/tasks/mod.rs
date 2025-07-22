use std::sync::Arc;

use tracing::info;

use crate::{app::AppState, tasks::expired_token::run};

pub mod expired_token;

pub async fn spawn_tasks(app_state: Arc<AppState>) {
    info!("Spawning background tasks...");
    tokio::spawn(run(app_state.clone()));

    info!("Tasks spawned successfully");
}
