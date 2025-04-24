mod raw;
mod resolved;

use std::{ops::Deref, path::Path, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
pub use resolved::*;

#[derive(Debug, Clone)]
pub struct ProxyConfig(Arc<ArcSwap<ProxyConfigResolved>>);

impl ProxyConfig {
    pub fn new(config: ProxyConfigResolved) -> Self {
        Self(Arc::new(ArcSwap::new(Arc::new(config))))
    }

    pub fn load_from_file(file: impl AsRef<Path>) -> Result<Self> {
        let config = ProxyConfigResolved::load(file)?;
        Ok(Self::new(config))
    }

    pub fn update(&self, config: ProxyConfigResolved) {
        self.store(Arc::new(config));
    }

    pub fn get_full(&self) -> Arc<ProxyConfigResolved> {
        self.load_full()
    }
}

impl Deref for ProxyConfig {
    type Target = ArcSwap<ProxyConfigResolved>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
