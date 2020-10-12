use std::time::Duration;

use crates_index::Index;
use tokio::task::spawn_blocking;
use tokio::time::{self, Interval};

pub struct ManagedIndex {
    index: Index,
    update_interval: Interval,
}

impl ManagedIndex {
    pub fn new(update_interval: Duration) -> Self {
        // the index path is configurable through the `CARGO_HOME` env variable
        let index = Index::new_cargo_default();
        let update_interval = time::interval(update_interval);
        Self {
            index,
            update_interval,
        }
    }

    pub fn index(&self) -> Index {
        self.index.clone()
    }

    pub async fn refresh_at_interval(&mut self) {
        loop {
            self.refresh().await;
            self.update_interval.tick().await;
        }
    }

    async fn refresh(&self) {
        let index = self.index();

        let _ = spawn_blocking(move || index.retrieve_or_update()).await;
    }
}