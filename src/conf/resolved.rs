use anyhow::{Context, Result, anyhow};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::convert::TryFrom;
use std::{collections::HashMap, path::Path};

use super::raw::{GlobalConfig, ServerConfig, SimpleProxyConfig, TlsConfig, UpstreamConfig};

#[derive(Debug, Clone)]
pub struct ProxyConfigResolved {
    pub global: GlobalConfigResolved,
    pub servers: HashMap<String, ServerConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfigResolved {
    pub port: u16,
    pub tls: Option<TlsConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct TlsConfigResolved {
    pub cert: String,
    pub key: String,
    pub ca: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConfigResolved {
    pub tls: bool,
    pub upstream: UpstreamConfigResolved,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfigResolved {
    pub servers: Vec<String>,
}

impl TryFrom<&GlobalConfig> for GlobalConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: &GlobalConfig) -> Result<Self> {
        let tls = raw
            .tls
            .as_ref()
            .map(TlsConfigResolved::try_from)
            .transpose()?;
        Ok(Self {
            port: raw.port,
            tls,
        })
    }
}

impl TryFrom<&TlsConfig> for TlsConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: &TlsConfig) -> Result<Self> {
        // Add error context for better diagnostics
        let cert_path = raw.cert.as_path();
        let key_path = raw.key.as_path();

        cert_path
            .exists()
            .then_some(())
            .with_context(|| format!("Certificate file not found: {}", cert_path.display()))?;

        key_path
            .exists()
            .then_some(())
            .with_context(|| format!("Private key file not found: {}", key_path.display()))?;

        let ca = if let Some(ca_path) = &raw.ca {
            if !ca_path.exists() {
                return Err(anyhow::anyhow!("CA file not found: {:?}", ca_path));
            }
            Some(ca_path.to_string_lossy().to_string())
        } else {
            None
        };
        Ok(Self {
            cert: cert_path.to_string_lossy().to_string(),
            key: key_path.to_string_lossy().to_string(),
            ca,
        })
    }
}

impl From<&UpstreamConfig> for UpstreamConfigResolved {
    fn from(raw: &UpstreamConfig) -> Self {
        Self {
            servers: raw.servers.clone(),
        }
    }
}

impl ProxyConfigResolved {
    pub fn load(file: impl AsRef<Path>) -> Result<Self> {
        let raw = SimpleProxyConfig::from_yaml_file(file)?;
        let config: ProxyConfigResolved = raw.try_into()?;
        Ok(config)
    }
}

impl TryFrom<SimpleProxyConfig> for ProxyConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: SimpleProxyConfig) -> Result<Self> {
        let global = GlobalConfigResolved::try_from(&raw.global)?;
        let upstream_map: HashMap<_, _> = raw
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), UpstreamConfigResolved::from(u)))
            .collect();

        let mut servers = HashMap::new();
        for server in raw.servers {
            let resolved_server = ServerConfigResolved::try_from_with_maps(&server, &upstream_map)?;

            for server_name in server.server_name {
                if servers.contains_key(&server_name) {
                    return Err(anyhow!("Duplicate server name: {}", server_name));
                }
                servers.insert(server_name, resolved_server.clone());
            }
        }

        Ok(Self { global, servers })
    }
}

impl ServerConfigResolved {
    fn try_from_with_maps(
        server: &ServerConfig,
        upstream_map: &HashMap<String, UpstreamConfigResolved>,
    ) -> Result<Self> {
        // Get the tls setting, default to false if not specified
        let tls = server.tls.unwrap_or(false);

        // Get the upstream configuration
        let upstream_name = &server.upstream;
        let upstream = upstream_map
            .get(upstream_name)
            .ok_or_else(|| anyhow!("Upstream '{}' not found", upstream_name))?
            .clone();

        Ok(ServerConfigResolved { tls, upstream })
    }

    pub fn choose(&self) -> Option<&str> {
        let upstream = self.upstream.servers.choose(&mut OsRng);
        upstream.map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_conversion() -> Result<()> {
        // Create test config YAML
        let yaml_content = r#"
global:
  port: 8080
  tls: ~

servers:
  - server_name: [acme.com, www.acme.com]
    upstream: web_servers
    tls: false
  - server_name: [api.acme.com]
    upstream: api_servers
    tls: true

upstreams:
  - name: api_servers
    servers: [127.0.0.1:3001, 127.0.0.1:3002]
  - name: web_servers
    servers: [127.0.0.1:3003, 127.0.0.1:3004]
"#;

        // Test conversion
        let raw = SimpleProxyConfig::from_yaml_str(yaml_content)?;
        let resolved = ProxyConfigResolved::try_from(raw)?;

        // Verify global config
        assert_eq!(resolved.global.port, 8080);
        assert!(
            resolved.global.tls.is_none(),
            "Global TLS should be unconfigured"
        );

        // Verify servers
        let web_server = resolved.servers.get("www.acme.com").unwrap();
        assert!(!web_server.tls, "Web server TLS should be false");
        assert_eq!(
            web_server.upstream.servers,
            vec!["127.0.0.1:3003", "127.0.0.1:3004"],
            "Web upstream servers should match"
        );

        let api_server = resolved.servers.get("api.acme.com").unwrap();
        assert!(api_server.tls, "API server TLS should be true");
        assert_eq!(
            api_server.upstream.servers,
            vec!["127.0.0.1:3001", "127.0.0.1:3002"],
            "API upstream servers should match"
        );

        Ok(())
    }
}
