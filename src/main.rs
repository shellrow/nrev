pub mod capture;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod db;
pub mod dns;
pub mod endpoint;
pub mod interface;
pub mod log;
pub mod nei;
pub mod os;
pub mod output;
pub mod packet;
pub mod ping;
pub mod probe;
pub mod protocol;
pub mod scan;
pub mod service;
pub mod time;
pub mod trace;
pub mod util;

use clap::Parser;
use cli::{Cli, Command};

use crate::db::DbInitializer;

#[tokio::main]
async fn main() {
    let exit_code = match run().await {
        Ok(_) => 0,
        Err(e) => {
            tracing::error!("{}", e);
            1
        }
    };
    std::process::exit(exit_code);
}

async fn run() -> anyhow::Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    // Initialize logger
    let _ = log::init_logger(&cli);
    // Start nrev
    let start_time = std::time::Instant::now();
    tracing::info!("nrev v{} started", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Command::Port(args) => {
            DbInitializer::with_all().init().await;
            cmd::port::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Port scan failed: {}", e))?;
        }
        Command::Host(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_os_db().with_oui_db().init().await;

            cmd::host::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Host scan failed: {}", e))?;
        }
        Command::Ping(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_os_db().with_oui_db().init().await;

            cmd::ping::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Ping failed: {}", e))?;
        }
        Command::Trace(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_oui_db().init().await;

            cmd::trace::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Trace failed: {}", e))?;
        }
        Command::Nei(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_oui_db().init().await;

            cmd::nei::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Neighbor discovery failed: {}", e))?;
        }
        Command::Domain(args) => {
            cmd::domain::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Domain scan failed: {}", e))?;
        }
        Command::Interface(args) => {
            cmd::interface::show(&args)
                .map_err(|e| anyhow::anyhow!("Show interfaces failed: {}", e))?;
        }
    }
    tracing::info!(
        "nrev v{} completed in {:?}",
        env!("CARGO_PKG_VERSION"),
        start_time.elapsed()
    );
    Ok(())
}
