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
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_resolved_conversion() -> Result<()> {
        // Create test certificates
        let temp_dir = tempdir()?;
        let create_cert = |dir: &str| -> Result<(PathBuf, PathBuf)> {
            let cert_dir = temp_dir.path().join(dir);
            fs::create_dir_all(&cert_dir)?;

            let cert_path = cert_dir.join("cert.pem");
            let key_path = cert_dir.join("key.pem");

            let mut cert_file = File::create(&cert_path)?;
            cert_file.write_all(b"test_cert")?;

            let mut key_file = File::create(&key_path)?;
            key_file.write_all(b"test_key")?;

            Ok((cert_path, key_path))
        };

        let (proxy_cert, proxy_key) = create_cert("proxy")?;
        let (web_cert, web_key) = create_cert("web")?;

        // Create test config YAML
        let yaml_content = format!(
            r#"
global:
  port: 8080
  tls: proxy_cert
certs:
  - name: proxy_cert
    cert_path: {}
    key_path: {}
  - name: web_cert
    cert_path: {}
    key_path: {}
servers:
  - server_name: [acme.com]
    upstream: web_servers
    tls: web_cert
upstreams:
  - name: web_servers
    servers: [127.0.0.1:3001]
"#,
            proxy_cert.display(),
            proxy_key.display(),
            web_cert.display(),
            web_key.display()
        );

        // Test conversion
        let raw = SimpleProxyConfig::from_yaml_str(&yaml_content)?;
        let resolved = ProxyConfigResolved::try_from(raw)?;

        // Verify global config
        assert_eq!(resolved.global.port, 8080);
        let global_cert = resolved.global.tls.unwrap();
        assert_eq!(global_cert.cert, "test_cert");
        assert_eq!(global_cert.key, "test_key");

        // Verify server config
        let server = resolved.servers.get("acme.com").unwrap();
        assert_eq!(server.upstream.servers, vec!["127.0.0.1:3001"]);

        Ok(())
    }
}
