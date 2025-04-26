use std::time::Duration;

use crate::conf::{ProxyConfig, ProxyConfigResolved};
use crate::get_host_port;
use async_trait::async_trait;
use axum::http::{self, StatusCode, header};
use bytes::Bytes;
use pingora::modules::http::HttpModules;
use pingora::protocols::Digest;
use pingora::protocols::http::conditional_filter;
use pingora::proxy::PurgeStatus;
use pingora::{
    http::ResponseHeader, modules::http::compression::ResponseCompressionBuilder, prelude::*,
    upstreams::peer::Peer,
};
use pingora_cache::key::HashBinary;
use pingora_cache::{
    CacheKey, CacheMeta, NoCacheReason, RespCacheable, RespCacheable::Uncacheable,
};
use tracing::{info, warn};

use super::{ProxyContext, RouteTable, SimpleProxy};

impl SimpleProxy {
    pub fn try_new(config: ProxyConfigResolved) -> anyhow::Result<Self> {
        let route_table = RouteTable::try_new(&config)?;
        Ok(Self {
            config: ProxyConfig::new(config),
            route_table,
        })
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.route_table
    }
}

// 最新版本的Rust已经可以不需要async_trait了
// 但是Pingora当前版本依赖了async_trait
// 所以这里需要使用async_trait
#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ProxyContext;

    // 1. 初始化上下文
    fn new_ctx(&self) -> Self::CTX {
        info!("new_ctx");
        ProxyContext {
            config: self.config.clone(),
            route_entry: None,
            port: 0,
            host: "".to_string(),
        }
    }

    // 2. 请求来到前的处理
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("early_request_filter");
        Ok(())
    }

    // 3. 请求来到的处理
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        info!("request_filter");
        // 根据请求的host，从route_table中获取对应的route_entry
        let (host, port) = get_host_port(
            session.get_header(http::header::HOST),
            &session.req_header().uri,
        );
        let rt = self.route_table.pin();
        let route_entry = rt.get(host);
        ctx.route_entry = route_entry.cloned();
        ctx.host = host.to_string();
        ctx.port = port;
        Ok(false)
    }

    // 4. 请求缓存处理
    fn request_cache_filter(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        info!("request_cache_filter");
        Ok(())
    }

    // 5.
    fn is_purge(&self, _session: &Session, _ctx: &Self::CTX) -> bool {
        info!("is_purge");
        false
    }

    // 6.
    async fn proxy_upstream_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("proxy_upstream_filter");
        Ok(true)
    }

    // 7.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        info!("upstream_peer");

        let Some(route_entry) = ctx.route_entry.as_ref() else {
            // return 404 if host is not found
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::NOT_FOUND.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let Some(upstream) = route_entry.select() else {
            // return 404 if host is not found
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::BAD_GATEWAY.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };

        let mut peer = HttpPeer::new(upstream, route_entry.tls, ctx.host.clone());
        if let Some(options) = peer.get_mut_peer_options() {
            options.set_http_version(2, 2); // 启用 HTTP/2
        }
        info!("upstream peer: {}", peer);
        Ok(Box::new(peer))
    }

    // 8.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        _digest: Option<&Digest>,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!("connected_to_upstream");
        Ok(())
    }

    // 9.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        info!("upstream_request_filter");
        upstream_request.insert_header("x-simple-version", "v0.1")?;
        upstream_request.insert_header("user-agent", "SimpleProxy/0.1")?;
        Ok(())
    }

    // 10.
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) {
        info!("upstream_response_filter");
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

    // 11.
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("response_filter");
        Ok(())
    }

    // 12.
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) {
        info!("upstream_response_body_filter");
    }

    // 13.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        info!("response_body_filter");
        Ok(None)
    }

    // 14.
    async fn logging(&self, session: &mut Session, e: Option<&Error>, _ctx: &mut Self::CTX) {
        info!("logging for {}", session.request_summary());
        if let Some(err) = e {
            warn!("request error: {}", err);
        }
    }

    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        info!("initializing_downstream_modules");
        modules.add_module(ResponseCompressionBuilder::enable(0));
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("request_body_filter");
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
        info!("cache_key_callback");
        Ok(CacheKey::default(session.req_header()))
    }

    fn cache_miss(&self, session: &mut Session, _ctx: &mut Self::CTX) {
        info!("cache_miss");
        session.cache.cache_miss();
    }

    async fn cache_hit_filter(
        &self,
        _session: &Session,
        _meta: &CacheMeta,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("cache_hit_filter");
        Ok(false)
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        _resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        info!("response_cache_filter");
        Ok(Uncacheable(NoCacheReason::Custom("default")))
    }

    fn cache_vary_filter(
        &self,
        _meta: &CacheMeta,
        _ctx: &mut Self::CTX,
        _req: &RequestHeader,
    ) -> Option<HashBinary> {
        info!("cache_vary_filter");
        None
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, _error: &Error) -> bool {
        info!("error_suppression");
        false
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        _ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        info!("error_while_proxy");
        let mut e = e.more_context(format!("Peer: {}", peer));
        e.retry
            .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
        e
    }

    fn cache_not_modified_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("cache_not_modified_filter");
        Ok(conditional_filter::not_modified_filter(
            session.req_header(),
            resp,
        ))
    }

    /// Similar to [Self::upstream_response_filter()] but for response trailers
    fn upstream_response_trailer_filter(
        &self,
        _session: &mut Session,
        _upstream_trailers: &mut header::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("upstream_response_trailer_filter");
        Ok(())
    }

    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        _upstream_trailers: &mut header::HeaderMap,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<Bytes>>
    where
        Self::CTX: Send + Sync,
    {
        info!("response_trailer_filter");
        Ok(None)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        info!("fail_to_connect");
        e
    }

    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, _ctx: &mut Self::CTX) -> u16
    where
        Self::CTX: Send + Sync,
    {
        info!("fail_to_proxy");
        let server_session = session.as_mut();
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => {
                match e.esource() {
                    ErrorSource::Upstream => 502,
                    ErrorSource::Downstream => {
                        match e.etype() {
                            WriteError | ReadError | ConnectionClosed => {
                                /* conn already dead */
                                0
                            }
                            _ => 400,
                        }
                    }
                    ErrorSource::Internal | ErrorSource::Unset => 500,
                }
            }
        };
        if code > 0 {
            server_session.respond_error(code).await
        }
        code
    }

    fn should_serve_stale(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        error: Option<&Error>, // None when it is called during stale while revalidate
    ) -> bool {
        info!("should_serve_stale");
        error.is_some_and(|e| e.esource() == &ErrorSource::Upstream)
    }

    fn request_summary(&self, session: &Session, _ctx: &Self::CTX) -> String {
        info!("request_summary");
        session.as_ref().request_summary()
    }

    fn purge_response_filter(
        &self,
        _session: &Session,
        _ctx: &mut Self::CTX,
        _purge_status: PurgeStatus,
        _purge_response: &mut std::borrow::Cow<'static, ResponseHeader>,
    ) -> Result<()> {
        info!("purge_response_filter");
        Ok(())
    }
}
