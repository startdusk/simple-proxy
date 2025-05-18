use std::{ops::Deref, sync::Arc};

use bytes::BytesMut;
// 为什么不使用dashmap呢？proxy的场景下，route都是固定的，不需要动态增删。读比较多
// 因为papaya在读多写少的场景下，性能更好。
use papaya::HashMap;
use pingora::lb::{
    LoadBalancer,
    selection::{algorithms::RoundRobin, weighted::Weighted},
};

use crate::conf::ProxyConfig;

mod health;
mod route;
mod simple_proxy;

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
    pub(crate) route_table: RouteTable,
}

#[allow(unused)]
pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
    pub(crate) route_entry: Option<RouteEntry>,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) resp_content_type: Option<String>,
    pub(crate) resp_body: Option<BytesMut>,
}

#[derive(Clone)]
pub struct RouteTable(pub(crate) Arc<HashMap<String, RouteEntry>>);

#[derive(Clone)]
pub struct RouteEntry {
    pub(crate) upstream: Arc<LoadBalancer<Weighted<RoundRobin>>>,
    pub(crate) tls: bool,
}

pub struct HealthService {
    pub(crate) route_table: RouteTable,
}

impl Deref for RouteTable {
    type Target = HashMap<String, RouteEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
