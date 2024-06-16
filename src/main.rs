use anyhow::Result;
use std::env;
use std::fs;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use wtransport::endpoint::IncomingSession;
use wtransport::Endpoint;
use wtransport::ServerConfig;
mod cert_resolver;

#[derive(serde::Deserialize)]
struct Config {
    bind: Option<String>,
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("specify a config file");
        exit(1);
    }
    let config_file = fs::read_to_string(&args[1])
        .map_err(|err| {
            error!("failed to load config file: {}", err);
            exit(1);
        })
        .unwrap();
    let config: Config = toml::from_str(&config_file)
        .map_err(|err| {
            error!("failed to parse config file: {}", err);
            exit(1);
        })
        .unwrap();
    let mut tls_config = wtransport::config::TlsServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver::ResolvesServerCertUsingSni::new(
            config.host,
        )));
    tls_config.alpn_protocols = [wtransport::tls::WEBTRANSPORT_ALPN.to_vec()].to_vec();

    let config: ServerConfig = config
        .bind
        .map_or_else(
            || ServerConfig::builder().with_bind_default(config.port),
            |bind| {
                ServerConfig::builder()
                    .with_bind_address(bind.parse::<core::net::SocketAddr>().unwrap())
            },
        )
        .with_custom_tls(tls_config)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let server = Endpoint::server(config)?;

    info!("Server ready!");

    for id in 0.. {
        let incoming_session = server.accept().await;
        tokio::spawn(handle_connection(incoming_session).instrument(info_span!("Connection", id)));
    }

    Ok(())
}

async fn handle_connection(incoming_session: IncomingSession) {
    let result = handle_connection_impl(incoming_session).await;
    if result.is_err() {
        error!("{:?}", result.unwrap_err());
    }
}

async fn handle_connection_impl(incoming_session: IncomingSession) -> Result<()> {
    let mut buffer: [u8; 65536] = [0; 65536];

    info!("Waiting for session request...");

    let session_request = incoming_session.await?;

    info!(
        "New session: Authority: '{}', Path: '{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection = session_request.accept().await?;
    let mut stream = connection.open_bi().await?.await?;
    loop {
        let read = stream.1.read(buffer.as_mut()).await?;
        if read.is_some() {
            stream.0.write(&buffer[0..read.unwrap()]).await?;
        }
    }
}

fn init_logging() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(env_filter)
        .init();
}
