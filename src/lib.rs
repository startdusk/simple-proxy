pub mod conf;

use async_trait::async_trait;
use axum::http::{self, StatusCode};
use conf::ProxyConfig;
use pingora::{http::ResponseHeader, prelude::*};
use tracing::{info, warn};

pub struct SimpleProxy {
    pub(crate) config: ProxyConfig,
}

impl SimpleProxy {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }
}

#[allow(unused)]
pub struct ProxyContext {
    pub(crate) config: ProxyConfig,
}

// 最新版本的Rust已经可以不需要async_trait了
// 但是Pingora当前版本依赖了async_trait
// 所以这里需要使用async_trait
#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext {
            config: self.config.clone(),
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let config = self.config.load();
        let Some(host) = session
            .get_header(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| {
                // remove port if exists
                h.split(':').next().unwrap_or(h)
            })
        else {
            // return 404 if host is not found
            return Err(Error::create(
                ErrorType::CustomCode("No valid host found", StatusCode::BAD_REQUEST.into()),
                ErrorSource::Downstream,
                None,
                None,
            ));
        };

        let Some(server) = config.servers.get(host) else {
            // return 404 if host is not found
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::NOT_FOUND.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let Some(upstream) = server.choose() else {
            // return 503 if no upstream is available
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::SERVICE_UNAVAILABLE.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let peer = HttpPeer::new(upstream, false, host.to_string());
        info!("upstream peer: {}", peer);
        Ok(Box::new(peer))
    }

    /// Modify the request before it is sent to the upstream
    ///
    /// Unlike [Self::request_filter()], this filter allows to change the request headers to send
    /// to the upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!("upstream request filter: {:?}", upstream_request);
        upstream_request.insert_header("x-simple-version", "v0.1")?;
        upstream_request.insert_header("user-agent", "SimpleProxy/0.1")?;
        Ok(())
    }

    /// Modify the response header from the upstream
    ///
    /// The modification is before caching, so any change here will be stored in the cache if enabled.
    ///
    /// Responses served from cache won't trigger this filter. If the cache needed revalidation,
    /// only the 304 from upstream will trigger the filter (though it will be merged into the
    /// cached header, not served directly to downstream).
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) {
        info!("upstream response filter: {:?}", upstream_response);
        if upstream_response.headers.get("x-simple-proxy").is_none() {
            if let Err(e) = upstream_response.insert_header("x-simple-proxy", "v0.1") {
                warn!("failed to insert server header: {}", e);
            }
        }
        if upstream_response.headers.get("server").is_none() {
            if let Err(e) = upstream_response.insert_header("server", "SimpleProxy/1.0") {
                warn!("failed to insert server header: {}", e);
            }
        }
    }
}
