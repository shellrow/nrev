use clap::{crate_name, crate_version, crate_description};
use nerum_core::sys;

// APP information
pub const CRATE_BIN_NAME: &str = "nerum";
pub const CRATE_UPDATE_DATE: &str = "2024-06-09";
pub const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nerum";

pub enum AppCommands {
    PortScan,
    HostScan,
    Ping,
    Trace,
    Subdomain,
    Neighbor,
    Interfaces,
    Interface,
    CheckDependencies,
}

impl AppCommands {
    pub fn from_str(s: &str) -> Option<AppCommands> {
        match s {
            "port" => Some(AppCommands::PortScan),
            "host" => Some(AppCommands::HostScan),
            "ping" => Some(AppCommands::Ping),
            "trace" => Some(AppCommands::Trace),
            "subdomain" => Some(AppCommands::Subdomain),
            "nei" => Some(AppCommands::Neighbor),
            "interfaces" => Some(AppCommands::Interfaces),
            "interface" => Some(AppCommands::Interface),
            "check" => Some(AppCommands::CheckDependencies),
            _ => None
        }
    }
}

pub fn show_app_desc() {
    println!(
        "{} v{} ({}) {}",
        crate_name!(),
        crate_version!(),
        CRATE_UPDATE_DATE,
        sys::os::get_os_type()
    );
    println!("{}", crate_description!());
    println!("{}", CRATE_REPOSITORY);
    println!();
    println!("'{} --help' for more information.", CRATE_BIN_NAME);
    println!();
}

pub fn show_banner_with_starttime() {
    println!(
        "{} v{} {}",
        crate_name!(),
        crate_version!(),
        sys::os::get_os_type()
    );
    println!("{}", CRATE_REPOSITORY);
    println!();
    println!("Starting at {}", sys::time::get_sysdate());
    println!();
}

pub fn exit_with_error_message(message: &str) {
    println!();
    println!("Error: {}", message);
    std::process::exit(1);
}
