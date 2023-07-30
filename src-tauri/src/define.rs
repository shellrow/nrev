// MPSC(Multi Producer, Single Consumer) FIFO queue communication messages
pub const MESSAGE_START_PORTSCAN: &str = "START_PORTSCAN";
pub const MESSAGE_END_PORTSCAN: &str = "END_PORTSCAN";
pub const MESSAGE_START_SERVICEDETECTION: &str = "START_SERVICEDETECTION";
pub const MESSAGE_END_SERVICEDETECTION: &str = "END_SERVICEDETECTION";
pub const MESSAGE_START_OSDETECTION: &str = "START_OSDETECTION";
pub const MESSAGE_END_OSDETECTION: &str = "END_OSDETECTION";
pub const MESSAGE_START_HOSTSCAN: &str = "START_HOSTSCAN";
pub const MESSAGE_END_HOSTSCAN: &str = "END_HOSTSCAN";
pub const MESSAGE_START_LOOKUP: &str = "START_LOOKUP";
pub const MESSAGE_END_LOOKUP: &str = "END_LOOKUP";

// Database
pub const DB_NAME: &str = "nmdb.db";

// env
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_RELEASE_DATE: &str = "2023-07-30";
pub const APP_REPOSITORY : &str = env!("CARGO_PKG_REPOSITORY");
