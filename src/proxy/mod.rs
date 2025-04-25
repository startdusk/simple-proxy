use crate::conf::ProxyConfig;

mod health;
mod route;
mod simple_proxy;

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
}

#[allow(unused)]
pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
}
