use std::path::PathBuf;

use pingora::{
    listeners::tls::TlsSettings,
    proxy::http_proxy_service,
    server::{Server, configuration::ServerConf},
};
use simple_proxy::{HealthService, SimpleProxy, conf::ProxyConfigResolved};
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let args = Args::parse();

    let config = ProxyConfigResolved::load(&args.config)?;
    let tls_settings = {
        match config.global.tls.as_ref() {
            Some(tls) => {
                let mut tls_settings = TlsSettings::intermediate(&tls.cert, &tls.key)?;
                tls_settings.enable_h2(); // 启用 HTTP/2
                info!("tls settings enabled HTTP/2");
                Some(tls_settings)
            }
            None => None,
        }
    };

    let proxy_addr = format!("0.0.0.0:{}", config.global.port);
    let conf = {
        let ca_file = config.global.tls.as_ref().and_then(|tls| tls.ca.clone());
        ServerConf {
            ca_file,
            ..Default::default()
        }
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let sp = SimpleProxy::try_new(config)?;
    let health_service = HealthService::new(sp.route_table().clone());
    let mut proxy = http_proxy_service(&server.configuration, sp);
    match tls_settings {
        Some(tls_settings) => {
            info!("proxy listening on {} with TLS", proxy_addr);
            proxy.add_tls_with_settings(&proxy_addr, None, tls_settings);
        }
        None => {
            info!("proxy listening on {} without TLS", proxy_addr);
            proxy.add_tcp(&proxy_addr);
        }
    }

    server.add_service(proxy);
    server.add_service(health_service);
    server.run_forever();
}
