use pingora::{proxy::http_proxy_service, server::Server};
use simple_proxy::SimpleProxy;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    let mut server = Server::new(None)?;
    server.bootstrap();
    let sp = SimpleProxy {};
    let proxy_addr = "0.0.0.0:8080";
    let mut proxy = http_proxy_service(&server.configuration, sp);
    proxy.add_tcp(proxy_addr);

    info!("proxy listening on {}", proxy_addr);

    server.add_service(proxy);
    server.run_forever();
}
