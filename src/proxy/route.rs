use std::{sync::Arc, time::Duration};

use anyhow::Result;
use papaya::HashMap;
use pingora::{
    lb::{Backend, LoadBalancer},
    prelude::TcpHealthCheck,
};
use tracing::info;

use crate::conf::{ProxyConfigResolved, ServerConfigResolved};

use super::{RouteEntry, RouteTable};

const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

impl RouteTable {
    pub fn try_new(config: &ProxyConfigResolved) -> Result<Self> {
        let route_table = HashMap::new();
        {
            let pinned = route_table.pin();
            for (server_name, server) in &config.servers {
                pinned.insert(server_name.clone(), RouteEntry::try_new(server)?);
            }
        }
        Ok(Self(Arc::new(route_table)))
    }
}

impl RouteEntry {
    pub fn try_new(config: &ServerConfigResolved) -> Result<Self> {
        let mut lb = LoadBalancer::try_from_iter(&config.upstream.servers)?;
        let hc = TcpHealthCheck::new();
        lb.set_health_check(hc);
        lb.health_check_frequency = Some(HEALTH_CHECK_INTERVAL);
        Ok(Self {
            tls: config.tls,
            upstream: Arc::new(lb),
        })
    }

    pub fn select(&self) -> Option<Backend> {
        let accept = |b: &Backend, healthy: bool| {
            info!("select backend: {:?}, healthy: {}", b, healthy);
            healthy
        };
        self.upstream.select_with(b"", 32, accept)
    }
}
