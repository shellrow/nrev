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
            let r = cmd::port::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Port scan failed: {}", e),
            }
        }
        Command::Host(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_os_db().with_oui_db().init().await;

            let r = cmd::host::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Host scan failed: {}", e),
            }
        }
        Command::Ping(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_os_db().with_oui_db().init().await;

            let r = cmd::ping::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Ping failed: {}", e),
            }
        }
        Command::Trace(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_oui_db().init().await;

            let r = cmd::trace::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Trace failed: {}", e),
            }
        }
        Command::Nei(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_oui_db().init().await;

            let r = cmd::nei::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Neighbor discovery failed: {}", e),
            }
        }
        Command::Domain(args) => {
            let r = cmd::domain::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Domain scan failed: {}", e),
            }
        }
        Command::Interface(args) => {
            let r = cmd::interface::show(&args);
            match r {
                Ok(_) => {}
                Err(e) => tracing::error!("Show interfaces failed: {}", e),
            }
        }
    }
    tracing::info!(
        "nrev v{} completed in {:?}",
        env!("CARGO_PKG_VERSION"),
        start_time.elapsed()
    );
}
