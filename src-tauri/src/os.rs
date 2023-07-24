use netscan::os::TcpFingerprint;
use crate::db_models::{OsFingerprint, OsTtl};
use crate::{db, network};

pub fn verify_os_fingerprint(fingerprint: TcpFingerprint) -> OsFingerprint {
    let mut result: OsFingerprint = OsFingerprint::new();
    if fingerprint.tcp_syn_ack_fingerprint.len() == 0 {
        return result;
    }
    let mut tcp_options: Vec<String> = vec![];
    for f in &fingerprint.tcp_syn_ack_fingerprint {
        let mut options: Vec<String> = vec![];
        f.tcp_option_order.iter().for_each(|option| {
            options.push(option.name());
        });
        tcp_options.push(options.join("-"));
    }
    let tcp_window_size: u16  = fingerprint.tcp_syn_ack_fingerprint[0].tcp_window_size;
    let tcp_option_pattern: String = tcp_options.join("|");
    // 1. Select exact match OS fingerprint
    let fingerprints: Vec<OsFingerprint> = db::search_os_fingerprints(tcp_window_size, tcp_option_pattern.clone());
    if fingerprints.len() > 0 {
        return fingerprints[0].clone();
    }
    // 2. Select OS fingerprint that most closely approximates
    let fingerprints: Vec<OsFingerprint> = db::get_approximate_fingerprints(tcp_window_size, tcp_option_pattern);
    if fingerprints.len() > 0 {
        return fingerprints[0].clone();
    }
    // 3. from TTL
    let initial_ttl = network::guess_initial_ttl(fingerprint.ip_ttl);
    let os_ttl: OsTtl = db::get_os_family(initial_ttl);
    if !os_ttl.os_family.is_empty() {
        result.cpe = String::from("(Failed to OS Fingerprinting)");
        result.os_family = os_ttl.os_family;
        result.os_name = os_ttl.os_description;
    }
    result
}
