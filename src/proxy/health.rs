use std::time::Duration;

use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time::interval;
use tracing::info;

use super::{HealthService, RouteTable};

const HEALTH_SERVICE_INTERVAL: Duration = Duration::from_secs(5);

impl HealthService {
    pub fn new(route_table: RouteTable) -> Self {
        Self { route_table }
    }
}

#[async_trait]
impl Service for HealthService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        _shutdown: ShutdownWatch,
    ) {
        info!("Starting health service");
        let mut interval = interval(HEALTH_SERVICE_INTERVAL);
        let route_table = self.route_table.pin_owned();
        loop {
            interval.tick().await;
            for (host, entry) in route_table.iter() {
                info!("Checking health for host: {}", host);

                entry.upstream.update().await.ok();
                entry.upstream.backends().run_health_check(true).await;
            }
        }
    }

    fn name(&self) -> &str {
        "health_check"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
