//! Network discovery, port scanning, and service observations.
//!
//! TLS probing collects certificates without establishing server trust.
//! Raw-packet operations require platform-specific capture privileges.

pub mod capture;
pub mod cli;
pub mod config;
pub mod data;
pub mod error;
pub mod fingerprint;
pub mod host;
pub mod interface;
pub mod model;
pub mod neighbor;
pub mod output;
pub mod ping;
pub mod probes;
pub mod scanner;
pub mod service_db;
pub mod target;
pub mod tls;
pub mod trace;
pub mod transport;

pub mod nmap;
