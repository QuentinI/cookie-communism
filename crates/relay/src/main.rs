use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bpaf::Bpaf;
use cookie_communism_relay::{AppState, Config};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// cookie-communism relay: stores encrypted cookie envelopes and routes messages between
/// browser extensions and their consumers.
#[derive(Bpaf)]
#[bpaf(options, version)]
struct Args {
    /// Address to listen on. Put a TLS-terminating proxy in front of it.
    #[bpaf(env("CC_RELAY_LISTEN"), argument("ADDR"), fallback(SocketAddr::from(([127, 0, 0, 1], 8787))), display_fallback)]
    listen: SocketAddr,
    /// SQLite database path.
    #[bpaf(env("CC_RELAY_DATABASE"), argument("FILE"), fallback("relay.sqlite".into()), debug_fallback)]
    database: PathBuf,
    /// Owner public key allowed to register (repeatable, or comma-separated in the environment).
    /// With none, any owner may register, subject to --registration-secret.
    #[bpaf(long("allow-owner"), env("CC_RELAY_ALLOW_OWNERS"), argument("KEY"))]
    allow_owners: Vec<String>,
    /// Secret a new owner must present on its first invite.
    #[bpaf(env("CC_RELAY_REGISTRATION_SECRET"), argument("SECRET"))]
    registration_secret: Option<String>,
    /// Requests per key per minute.
    #[bpaf(
        env("CC_RELAY_RATE_LIMIT"),
        argument("N"),
        fallback(120),
        display_fallback
    )]
    rate_limit: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_target("cookie_communism_relay", Level::INFO));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();
    let args = args().run();
    if args.allow_owners.is_empty() && args.registration_secret.is_none() {
        tracing::warn!(
            "open registration: anyone can use this relay; set --allow-owner or --registration-secret"
        );
    }
    let state = AppState::new(Config {
        database: Some(args.database),
        allowed_owners: args
            .allow_owners
            .iter()
            .flat_map(|keys| keys.split(','))
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .collect(),
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
