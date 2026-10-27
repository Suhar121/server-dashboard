use crate::config::Config;
use crate::db::DbPool;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: DbPool,
    pub sys: Arc<Mutex<System>>,
}

impl AppState {
    pub fn new(config: Config, db: DbPool) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            config,
            db,
            sys: Arc::new(Mutex::new(sys)),
        }
    }
}
