use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleProxyConfig {
    pub global: GlobalConfig,
    pub servers: Vec<ServerConfig>,
    pub upstreams: Vec<UpstreamConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_name: Vec<String>,
    pub upstream: String,
    #[serde(default)]
    pub tls: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub servers: Vec<String>,
}

fn default_port() -> u16 {
    8080
}

impl SimpleProxyConfig {
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let config: Self = serde_yaml::from_reader(file)?;

        // Validate TLS file existence
        if let Some(tls) = &config.global.tls {
            if let Some(ca) = &tls.ca {
                ensure!(ca.exists(), "CA file not found: {}", ca.display());
            }
        }

        Ok(config)
    }

    pub fn from_yaml_str(s: &str) -> Result<Self> {
        let config: SimpleProxyConfig = serde_yaml::from_str(s)?;
        Ok(config)
    }

    pub fn to_yaml_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_yaml::to_writer(file, self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_sample_config() -> Result<()> {
        let config = SimpleProxyConfig::from_yaml_file("fixtures/sample.yml")?;

        // Verify global settings
        assert_eq!(config.global.port, 8080, "Default port should be 8080");
        assert!(
            config.global.tls.is_none(),
            "Global TLS should be unconfigured"
        ); // Fixed assertion

        // Verify servers
        let api_server = config
            .servers
            .iter()
            .find(|s| s.server_name.contains(&"api.acme.com".to_string()))
            .expect("API server should exist");
        assert_eq!(
            api_server.upstream, "api_servers",
            "API server upstream should match"
        );

        // Verify upstreams
        let web_upstream = config
            .upstreams
            .iter()
            .find(|u| u.name == "web_servers")
            .expect("Web upstream should exist");
        assert_eq!(
            web_upstream.servers,
            vec!["127.0.0.1:3003", "127.0.0.1:3004"], // Fixed expected servers
            "Web upstream servers should match"
        );

        Ok(())
    }

    #[test]
    fn test_config_roundtrip() -> Result<()> {
        let original = SimpleProxyConfig::from_yaml_file("fixtures/sample.yml")?;
        let yaml = serde_yaml::to_string(&original)?;
        let reloaded: SimpleProxyConfig = serde_yaml::from_str(&yaml)?;

        assert_eq!(original.global.port, reloaded.global.port);
        Ok(())
    }
}
