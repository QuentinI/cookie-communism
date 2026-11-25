use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use cookie_communism::{Client, Policy};
use futures::StreamExt;

/// Receive cookies from your browsers, end-to-end encrypted, through a cookie-communism relay.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// State file (keys, paired browsers, cached cookies). One per consumer.
    #[arg(long, global = true, env = "CCOM_STATE")]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair with a browser using an invite from the extension. Repeat to add more browsers.
    Pair {
        invite: String,
        /// Name shown in the extension.
        #[arg(long)]
        label: String,
        /// Cookie selector, `domain` or `domain:name` (repeatable).
        #[arg(long = "want", required = true)]
        wants: Vec<String>,
    },
    /// List paired browsers.
    Owners,
    /// Show each selector group: its policy, the browser supplying it, and expiry.
    Status,
    /// Set the policy for all groups, or for one selector with --selector.
    Policy {
        /// Applies to this selector (or, for a bare domain, every selector on it).
        #[arg(long)]
        selector: Option<String>,
        #[command(subcommand)]
        policy: PolicyArg,
    },
    /// Fetch new cookies once.
    Sync {
        /// Write the chosen cookies here as a Netscape cookies.txt.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fetch new cookies as they arrive, forever.
    Watch {
        /// Rewrite this Netscape cookies.txt on every change.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the chosen cookies (Netscape format, or JSON).
    Get {
        #[arg(long)]
        json: bool,
    },
    /// Report that the cookies for a selector stopped working.
    Fail {
        selector: String,
        #[arg(long, default_value = "reported from the command line")]
        reason: String,
    },
    /// Forget a paired browser locally (it should also revoke the grant in the extension).
    Forget { owner: String },
}

#[derive(Subcommand, Clone)]
enum PolicyArg {
    /// The browser whose key cookies expire last (the default).
    Longest {
        /// Cookie names to compare, for domain-wide selectors.
        #[arg(long)]
        by: Vec<String>,
    },
    /// The browser whose cookies changed most recently.
    Freshest,
    /// Keep the current browser while it works.
    Sticky {
        /// Browsers (label or ID) to try first when switching.
        #[arg(long)]
        prefer: Vec<String>,
    },
    /// Only this browser.
    Pinned { owner: String },
    /// Remove the --selector policy, falling back to the default.
    Clear,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cookie_communism=info,ccom=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let state = match cli.state {
        Some(p) => p,
        None => dirs::config_dir()
            .context("no config directory; pass --state")?
            .join("cookie-communism")
            .join("state.json"),
    };
    let open =
        || Client::open(&state).with_context(|| format!("opening {}; pair first", state.display()));

    match cli.command {
        Command::Pair {
            invite,
            label,
            wants,
        } => {
            let pending = Client::pair(&state, &invite, &label, &wants).await?;
            if !pending.overlaps().is_empty() {
                eprintln!(
                    "Warning: {} already supplies cookies for these domains. Make sure this browser is logged in to the same account.",
                    pending.overlaps().join(", ")
                );
            }
            eprintln!("Pairing code: {}", pending.code());
            eprintln!("Check that the extension shows the same code, then approve it there.");
            let client = pending.approved().await?;
            eprintln!("Approved. State saved to {}.", state.display());
            print_status(&client);
        }
        Command::Owners => {
            for o in open()?.owners() {
                let selectors: Vec<String> = o.selectors.iter().map(ToString::to_string).collect();
                println!(
                    "{}\t{}\t{}\t{}",
                    o.owner.label,
                    o.owner.id,
                    selectors.join(","),
                    o.snapshot_taken_at
                        .map(fmt_time)
                        .unwrap_or_else(|| "no snapshot yet".into()),
                );
            }
        }
        Command::Status => print_status(&open()?),
        Command::Policy { selector, policy } => {
            let client = open()?;
            let policy = match policy {
                PolicyArg::Longest { by } => Some(Policy::Longest { by }),
                PolicyArg::Freshest => Some(Policy::Freshest),
                PolicyArg::Sticky { prefer } => Some(Policy::Sticky { prefer }),
                PolicyArg::Pinned { owner } => Some(Policy::Pinned { owner }),
                PolicyArg::Clear => None,
            };
            let events = match (selector, policy) {
                (Some(s), p) => client.set_policy_for(&s, p)?,
                (None, Some(p)) => client.set_policy(p)?,
                (None, None) => bail!("`clear` needs --selector"),
            };
            events.iter().for_each(|e| eprintln!("{e}"));
            print_status(&client);
        }
        Command::Sync { out } => {
            let client = open()?;
            client.sync().await?.iter().for_each(|e| eprintln!("{e}"));
            if let Some(out) = out {
                write_jar(&client, &out)?;
            }
        }
        Command::Watch { out } => {
            let client = open()?;
            client.sync().await?.iter().for_each(|e| eprintln!("{e}"));
            if let Some(out) = &out {
                write_jar(&client, out)?;
            }
            let mut events = std::pin::pin!(client.watch());
            while let Some(event) = events.next().await {
                match event {
                    Ok(e) => {
                        eprintln!("{e}");
                        if let Some(out) = &out {
                            write_jar(&client, out)?;
                        }
                    }
                    Err(e) => eprintln!("error: {e}"),
                }
            }
        }
        Command::Get { json } => {
            let jar = open()?.jar();
            if json {
                println!("{}", serde_json::to_string_pretty(&jar.cookies)?);
            } else {
                print!("{}", jar.to_netscape());
            }
        }
        Command::Fail { selector, reason } => {
            let client = open()?;
            client
                .report_failure(&selector, &reason)
                .await?
                .iter()
                .for_each(|e| eprintln!("{e}"));
            print_status(&client);
        }
        Command::Forget { owner } => {
            let client = open()?;
            client
                .remove_owner(&owner)?
                .iter()
                .for_each(|e| eprintln!("{e}"));
        }
    }
    Ok(())
}

fn write_jar(client: &Client, out: &Path) -> Result<()> {
    let text = client.jar().to_netscape();
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        out.file_name()
            .context("--out must be a file")?
            .to_string_lossy()
    ));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, out).with_context(|| format!("writing {}", out.display()))
}

fn print_status(client: &Client) {
    for g in client.status() {
        let selectors: Vec<String> = g.selectors.iter().map(ToString::to_string).collect();
        let source = match (&g.owner, &g.unavailable) {
            (Some(o), _) => format!("from {o}"),
            (None, Some(why)) => format!("UNAVAILABLE: {why}"),
            (None, None) => "UNAVAILABLE".into(),
        };
        let expires = g
            .expires
            .map(|e| format!(", expires {}", fmt_time(e)))
            .unwrap_or_default();
        println!(
            "{} [{}] policy {}: {source}{expires}",
            g.domain,
            selectors.join(", "),
            g.policy
        );
    }
}

fn fmt_time(unix: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = unix - now;
    let (abs, suffix) = if delta >= 0 {
        (delta, "from now")
    } else {
        (-delta, "ago")
    };
    let human = match abs {
        a if a < 120 => format!("{a}s"),
        a if a < 7200 => format!("{}m", a / 60),
        a if a < 172_800 => format!("{}h", a / 3600),
        a => format!("{}d", a / 86400),
    };
    format!("{human} {suffix}")
}
