use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use cookie_communism_relay::{AppState, Config};

/// cookie-communism relay: stores encrypted cookie envelopes and routes messages between
/// browser extensions and their consumers.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on. Put a TLS-terminating proxy in front of it.
    #[arg(long, env = "CC_RELAY_LISTEN", default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// SQLite database path.
    #[arg(long, env = "CC_RELAY_DATABASE", default_value = "relay.sqlite")]
    database: PathBuf,
    /// Owner public key allowed to register (repeatable). With none, any owner may register,
    /// subject to --registration-secret.
    #[arg(
        long = "allow-owner",
        env = "CC_RELAY_ALLOW_OWNERS",
        value_delimiter = ','
    )]
    allow_owners: Vec<String>,
    /// Secret a new owner must present on its first invite.
    #[arg(long, env = "CC_RELAY_REGISTRATION_SECRET")]
    registration_secret: Option<String>,
    /// Requests per key per minute.
    #[arg(long, env = "CC_RELAY_RATE_LIMIT", default_value_t = 120)]
    rate_limit: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cookie_communism_relay=info,tower_http=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    if args.allow_owners.is_empty() && args.registration_secret.is_none() {
        tracing::warn!(
            "open registration: anyone can use this relay; set --allow-owner or --registration-secret"
        );
    }
    let state = AppState::new(Config {
        database: Some(args.database),
        allowed_owners: args.allow_owners.into_iter().collect(),
        registration_secret: args.registration_secret,
        rate_limit_per_minute: args.rate_limit,
    })?;

    let cleaner = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            cleaner.cleanup();
        }
    });

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("listening on {}", args.listen);
    axum::serve(listener, cookie_communism_relay::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
