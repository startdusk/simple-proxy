use std::time::Duration;

use crate::conf::{ProxyConfig, ProxyConfigResolved};
use crate::get_host_port;
use async_trait::async_trait;
use axum::http::{self, StatusCode, header};
use bytes::{Bytes, BytesMut};
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
use serde_json::Value;
use tracing::{error, info, warn};

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

    // 1. 初始化上下文 - 为每个新请求创建代理上下文
    // 包含代理配置、路由条目、主机和端口信息
    fn new_ctx(&self) -> Self::CTX {
        info!("new_ctx");
        ProxyContext {
            config: self.config.clone(),
            route_entry: None,
            port: 0,
            host: "".to_string(),
            resp_content_type: None,
            resp_body: None,
        }
    }

    // 2. 请求来到前的处理 - 在请求完全到达前执行的早期过滤
    // 可用于实现IP黑名单、速率限制等
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("early_request_filter");
        Ok(())
    }

    // 3. 请求来到的处理 - 主要请求过滤逻辑
    // 解析请求的host和port，从路由表中查找对应的路由条目
    // 并将找到的路由信息存入上下文
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        info!("request_filter");
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

    // 4. 请求缓存处理 - 决定是否缓存当前请求
    // 返回Ok表示允许缓存，Err表示不允许
    fn request_cache_filter(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        info!("request_cache_filter");
        Ok(())
    }

    // 5. 是否是清除缓存请求 - 判断当前请求是否为清除缓存请求
    // 返回true表示是清除缓存请求，false表示不是
    fn is_purge(&self, _session: &Session, _ctx: &Self::CTX) -> bool {
        info!("is_purge");
        false
    }

    // 6. 代理上游过滤 - 在转发请求到上游前执行
    // 返回Ok(true)表示继续处理，Ok(false)表示终止处理
    async fn proxy_upstream_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        info!("proxy_upstream_filter");
        Ok(true)
    }

    // 7. 选择上游节点 - 根据上下文中的路由信息选择合适的上游服务器
    // 如果找不到路由或上游节点，返回相应的错误
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

    // 8. 连接到上游服务器后的处理 - 在成功连接到上游服务器后执行
    // 可用于记录连接指标或执行连接后初始化
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

    // 9. 上游请求过滤 - 在转发请求到上游前修改请求头
    // 这里添加了自定义版本信息和User-Agent
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

    // 10. 上游响应过滤 - 处理从上游返回的响应头
    // 添加代理标识头(x-simple-proxy)和Server头
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) {
        info!("upstream_response_filter");
        // 获取响应的Content-Type
        if let Some(v) = upstream_response.headers.get(header::CONTENT_TYPE) {
            ctx.resp_content_type = Some(v.to_str().unwrap_or("").to_string());
        }

        // 重要！！！
        // 如果，我们要做response body的修改，由于body大部分都是JSON格式的，而JSON必须一次性返回给客户端，
        // 如果做了修改, 而Content-Length无法修改, 那么就会导致客户端根据Content-Length接收数据时
        // JSON格式的响应被截断, 导致客户端无法解析
        // 所以, 我们需要将Content-Length删除, 然后设置Transfer-Encoding为chunked
        // 这样客户端就可以流式接收数据了
        // 删除响应的Content-Length，因为我们也不知道响应的大小
        // 然后设置响应的Transfer-Encoding为chunked，告诉客户端，你尽管收数据，我也不知道数据有多大
        upstream_response.remove_header(&header::CONTENT_LENGTH);
        if let Err(e) = upstream_response.insert_header(header::TRANSFER_ENCODING, "chunked") {
            warn!("failed to insert transfer encoding header: {}", e);
        }

        // 添加自定义响应头
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

    // 11. 响应过滤 - 在发送响应给客户端前的最后处理阶段
    // 可用于修改最终响应或添加额外处理
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        info!("response_filter");
        Ok(())
    }

    // 12. 上游响应体过滤 - 处理从上游返回的响应体
    // 可用于修改或检查响应体内容
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) {
        info!("upstream_response_body_filter");
    }

    // 13. 响应体过滤 - 处理最终发送给客户端的响应体(原则上能不修改返回的响应就不要修改)
    // 因为http body是json的格式，json的响应是需要收集整齐才能响应的，不能流式响应
    // 所以这里需要收集body的数据，然后再重写body，会非餐耗时
    // 可以返回一个可选的延迟时间用于流控制
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        info!("response_body_filter");
        if let Some(body) = body {
            if let Some(resp_body) = &mut ctx.resp_body {
                resp_body.extend_from_slice(body);
            } else {
                let mut resp_body = BytesMut::new();
                resp_body.extend_from_slice(body);
                ctx.resp_body = Some(resp_body);
            }
        }
        if !end_of_stream {
            // 说明数据太大了，需要分多次收集, 先直接返回
            // 等收集完了, end_of_stream 为 true 时, 再处理
            // 下面的代码收集完body的数据后, 会重写body, 所以这里需要先返回
            *body = None;
            return Ok(None);
        }
        let Some(resp_body) = ctx.resp_body.take() else {
            // 表示body没有数据, 直接返回
            return Ok(None);
        };

        let resp_body = resp_body.freeze();

        // 这里只是演示如何对JSON的body进行重写
        // 实际应用中, 可能需要根据不同的请求头, 来判断是否需要重写body
        let Some(content_type) = ctx.resp_content_type.as_deref() else {
            // 表示body没有content-type, 直接返回
            return Ok(None);
        };

        // 如果content-type不是json, 直接返回
        if !content_type.starts_with("application/json") {
            return Ok(None);
        }

        let Ok(json_body) = serde_json::from_slice::<Value>(&resp_body) else {
            // 表示body不是json格式, 直接返回
            return Ok(None);
        };
        let json_body = match json_body {
            Value::Object(mut obj) => {
                obj.insert(
                    "x-simple-proxy".to_string(),
                    Value::String("v0.1".to_string()),
                );
                Value::Object(obj)
            }
            Value::Array(mut arr) => {
                for item in arr.iter_mut() {
                    if let Value::Object(obj) = item {
                        obj.insert(
                            "x-simple-proxy".to_string(),
                            Value::String("v0.1".to_string()),
                        );
                    }
                }
                Value::Array(arr)
            }
            _ => json_body,
        };

        // 重新设置body
        let mut data = Vec::new();
        if let Err(e) = serde_json::to_writer(&mut data, &json_body) {
            error!("failed to serialize json: {}", e);
            return Err(Error::create(
                ErrorType::HTTPStatus(StatusCode::INTERNAL_SERVER_ERROR.into()),
                ErrorSource::Upstream,
                None,
                None,
            ));
        };
        *body = Some(data.into());
        Ok(None)
    }

    // 14. 日志记录 - 请求处理完成后的日志记录
    // 记录请求摘要和可能的错误信息
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use once_cell::sync::Lazy;
    use tokio_test::io::Builder;

    static CONFIG: Lazy<ProxyConfigResolved> = Lazy::new(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
        ProxyConfigResolved::load("fixtures/app.yml").unwrap()
    });

    static BODY_DATA: & [u8] = br#"[{"created_at":"2025-05-18T13:27:08.077004Z","email":"test@example.com","id":13,"name":"test_user1","updated_at":"2025-05-18T13:27:08.077004Z","x-simple-proxy":"v0.1"},{"created_at":"2025-05-18T13:26:24.107614Z","email":"test@example.com","id":8,"name":"test_user2","updated_at":"2025-05-18T13:26:24.107614Z","x-simple-proxy":"v0.1"}]"#;

    async fn create_mock_session() -> Session {
        // request
        let req = b"GET /users HTTP/1.1\r\nHost: api.acme.com\r\n\r\n";
        // response - 使用与测试代码相同的body数据
        let mock_io = Builder::new().read(req).write(&[]).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    #[tokio::test]
    async fn test_simple_proxy() {
        let proxy = SimpleProxy::try_new(CONFIG.clone()).unwrap();
        let mut session = create_mock_session().await;
        let mut ctx = proxy.new_ctx();
        proxy
            .early_request_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        proxy.request_filter(&mut session, &mut ctx).await.unwrap();
        assert_eq!(ctx.host, "api.acme.com");
        assert_eq!(ctx.port, 80);
        assert!(ctx.route_entry.as_ref().unwrap().tls);
        let pass = proxy
            .proxy_upstream_filter(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(pass);

        let peer = proxy.upstream_peer(&mut session, &mut ctx).await.unwrap();
        // peer could be 127.0.0.1:3001 or 127.0.0.1:3002
        let peer_str = peer._address.to_string();
        assert!(peer_str == "127.0.0.1:3001" || peer_str == "127.0.0.1:3002");
        assert_eq!(peer.scheme.to_string(), "HTTPS");
        assert_eq!(peer.sni(), "api.acme.com");

        let mut req_header = RequestHeader::build(Method::GET, b"/users", None).unwrap();
        req_header.insert_header("host", "api.acme.com").unwrap();
        proxy
            .upstream_request_filter(&mut session, &mut req_header, &mut ctx)
            .await
            .unwrap();
        proxy
            .request_body_filter(&mut session, &mut None, true, &mut ctx)
            .await
            .unwrap();

        // response processing
        let mut res_header = ResponseHeader::build(StatusCode::OK, None).unwrap();
        res_header
            .insert_header("Content-Type", "application/json")
            .unwrap();
        res_header
            .insert_header("x-server-info", "127.0.0.1:3001")
            .unwrap();
        // 重要：移除Content-Length，因为我们使用了chunked编码
        res_header.remove_header(&header::CONTENT_LENGTH);
        res_header
            .insert_header("Transfer-Encoding", "chunked")
            .unwrap();
        res_header.insert_header("connection", "close").unwrap();
        res_header
            .insert_header("date", "Sat, 17 May 2025 18:27:43 GMT")
            .unwrap();
        proxy.upstream_response_filter(&mut session, &mut res_header, &mut ctx);
        proxy
            .response_filter(&mut session, &mut res_header, &mut ctx)
            .await
            .unwrap();
        let mut body = Some(Bytes::from_static(BODY_DATA));
        proxy.upstream_response_body_filter(&mut session, &mut body, true, &mut ctx);

        // 验证响应头
        assert_eq!(res_header.status, StatusCode::OK);
        assert_eq!(res_header.version, http::Version::HTTP_11);

        // 验证必须存在的头
        assert!(res_header.headers.contains_key("content-type"));
        assert!(res_header.headers.contains_key("x-server-info"));
        assert!(res_header.headers.contains_key("transfer-encoding"));
        assert!(res_header.headers.contains_key("connection"));
        assert!(res_header.headers.contains_key("date"));

        // 验证代理添加的头
        assert!(res_header.headers.contains_key("x-simple-proxy"));
        assert!(res_header.headers.contains_key("server"));

        // 验证具体值
        assert_eq!(
            res_header.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(res_header.headers.get("x-simple-proxy").unwrap(), "v0.1");
        assert_eq!(res_header.headers.get("server").unwrap(), "SimpleProxy/1.0");

        // 验证Content-Length不存在
        assert!(!res_header.headers.contains_key("content-length"));
        proxy
            .response_body_filter(&mut session, &mut body, true, &mut ctx)
            .unwrap();
        assert_eq!(body.unwrap(), Bytes::from_static(BODY_DATA));
    }
}
