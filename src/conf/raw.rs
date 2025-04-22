use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleProxyConfig {
    pub global: GlobalConfig,
    #[serde(default)]
    pub certs: Vec<CertConfig>,
    pub servers: Vec<ServerConfig>,
    pub upstreams: Vec<UpstreamConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertConfig {
    pub name: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_name: Vec<String>,
    pub upstream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub servers: Vec<String>,
}

// Helper enums and defaults
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TlsConfig {
    Enabled(String),
    Disabled,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerTls {
    Cert(String),
    Disabled,
}

impl Default for ServerTls {
    fn default() -> Self {
        Self::Disabled
    }
}

fn default_port() -> u16 {
    8080
}

impl SimpleProxyConfig {
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let config: SimpleProxyConfig = serde_yaml::from_reader(file)?;
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
    use std::path::Path;

    #[test]
    fn test_load_sample_config() -> Result<()> {
        let config = SimpleProxyConfig::from_yaml_file("fixtures/sample.yml")?;

        // Verify global settings
        assert_eq!(config.global.port, 8080);
        assert!(matches!(config.global.tls, Some(TlsConfig::Enabled(ref s)) if s == "proxy_cert"));

        // Verify certificates
        assert_eq!(config.certs.len(), 3);
        let web_cert = &config.certs[1];
        assert_eq!(web_cert.name, "web_cert");
        assert_eq!(web_cert.cert_path, Path::new("./web/cert.pem"));

        // Verify servers
        assert_eq!(config.servers.len(), 2);
        let api_server = &config.servers[1];
        assert_eq!(api_server.server_name, vec!["api.acme.com"]);
        assert!(api_server.tls.is_none());

        // Verify upstreams
        assert_eq!(config.upstreams.len(), 2);
        let web_upstream = &config.upstreams[0];
        assert_eq!(web_upstream.name, "web_servers");
        assert_eq!(
            web_upstream.servers,
            vec!["127.0.0.1:3001", "127.0.0.1:3002"]
        );

        let api_upstream = &config.upstreams[1];
        assert_eq!(api_upstream.name, "api_servers");
        assert_eq!(
            api_upstream.servers,
            vec!["127.0.0.1:3003", "127.0.0.1:3004"]
        );

        Ok(())
    }

    #[test]
    fn test_config_roundtrip() -> Result<()> {
        let original = SimpleProxyConfig::from_yaml_file("fixtures/sample.yml")?;
        let yaml = serde_yaml::to_string(&original)?;
        let reloaded: SimpleProxyConfig = serde_yaml::from_str(&yaml)?;

        assert_eq!(original.global.port, reloaded.global.port);
        assert_eq!(original.certs.len(), reloaded.certs.len());
        Ok(())
    }
}
