use std::path::PathBuf;

use pingora::{proxy::http_proxy_service, server::Server};
use simple_proxy::{SimpleProxy, conf::ProxyConfig};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let mut server = Server::new(None)?;
    server.bootstrap();
    let config = ProxyConfig::load_from_file(args.config)?;
    let sp = SimpleProxy::new(config);
    let port = sp.config().load().global.port;
    let proxy_addr = format!("0.0.0.0:{}", port);
    let mut proxy = http_proxy_service(&server.configuration, sp);
    proxy.add_tcp(&proxy_addr);

    info!("proxy listening on {}", proxy_addr);

    server.add_service(proxy);
    server.run_forever();
}
