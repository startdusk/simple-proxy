use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::convert::TryFrom;
use std::{collections::HashMap, fs::read_to_string};

use super::raw::{CertConfig, GlobalConfig, SimpleProxyConfig, TlsConfig, UpstreamConfig};

#[derive(Debug, Clone)]
pub struct ProxyConfigResolved {
    pub global: GlobalConfigResolved,
    pub servers: HashMap<String, ServerConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfigResolved {
    pub port: u16,
    pub tls: Option<CertConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct CertConfigResolved {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfigResolved {
    pub tls: Option<CertConfigResolved>,
    pub upstream: UpstreamConfigResolved,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfigResolved {
    pub servers: Vec<String>,
}

impl TryFrom<&GlobalConfig> for GlobalConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: &GlobalConfig) -> Result<Self> {
        Ok(Self {
            port: raw.port,
            tls: None, // Will be resolved in parent context
        })
    }
}

impl TryFrom<&CertConfig> for CertConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: &CertConfig) -> Result<Self> {
        Ok(Self {
            cert: read_to_string(&raw.cert_path)
                .with_context(|| format!("Failed to read cert: {:?}", raw.cert_path))?,
            key: read_to_string(&raw.key_path)
                .with_context(|| format!("Failed to read key: {:?}", raw.key_path))?,
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

impl TryFrom<SimpleProxyConfig> for ProxyConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: SimpleProxyConfig) -> Result<Self> {
        let mut cert_map = HashMap::new();
        for cert in &raw.certs {
            cert_map.insert(cert.name.clone(), CertConfigResolved::try_from(cert)?);
        }

        let global = GlobalConfigResolved {
            port: raw.global.port,
            tls: match &raw.global.tls {
                Some(TlsConfig::Enabled(name)) => cert_map.get(name).cloned(),
                _ => None,
            },
        };

        let upstream_map: HashMap<_, _> = raw
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), UpstreamConfigResolved::from(u)))
            .collect();

        let mut servers = HashMap::new();
        for server in &raw.servers {
            let server_tls = match &server.tls {
                Some(super::raw::ServerTls::Cert(name)) => cert_map.get(name).cloned(),
                _ => None,
            };

            let upstream = upstream_map
                .get(&server.upstream)
                .with_context(|| format!("Upstream {} not found", server.upstream))?
                .clone();

            for host in &server.server_name {
                servers.insert(
                    host.clone(),
                    ServerConfigResolved {
                        tls: server_tls.clone(),
                        upstream: upstream.clone(),
                    },
                );
            }
        }

        Ok(Self { global, servers })
    }
}

impl ServerConfigResolved {
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
        let server_cert = server.tls.as_ref().unwrap();
        assert_eq!(server_cert.cert, "test_cert");
        assert_eq!(server_cert.key, "test_key");
        assert_eq!(server.upstream.servers, vec!["127.0.0.1:3001"]);

        Ok(())
    }
}
