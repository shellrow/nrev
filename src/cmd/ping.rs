use std::{path::PathBuf, time::Duration};

use crate::{cli::PingArgs, endpoint::Host, ping::{pinger::Pinger, setting::PingSetting}, protocol::Protocol, util::json::{save_json_output, JsonStyle}};
use anyhow::Result;

/// Run ping command
pub async fn run(args: PingArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
    let interface: netdev::Interface = if let Some(if_name) = args.interface {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => anyhow::bail!("interface not found"),
        }
    } else {
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => anyhow::bail!("failed to get default interface"),
        }
    };
    let dst_host: Host = crate::cli::ping::parse_target_host(&args.target).await?;
    let mut ping_setting: PingSetting = match args.proto {
        Protocol::Icmp => PingSetting::icmp_ping(&interface, dst_host, args.count)?,
        Protocol::Tcp => PingSetting::tcp_ping(&interface, dst_host, args.port, args.count)?,
        Protocol::Udp => PingSetting::udp_ping(&interface, dst_host, args.count)?,
        _ => {
            anyhow::bail!("Unsupported protocol");
        }
    };
    ping_setting.send_rate = Duration::from_millis(args.interval_ms);
    ping_setting.receive_timeout = Duration::from_millis(args.timeout_ms);

    let pinger = Pinger::new(ping_setting);
    tracing::info!("Pinging {} with {}...", args.target, args.proto.as_str().to_uppercase());
    let ping_result = pinger.run().await?;
    if !no_stdout {
        crate::output::ping::print_ping_tree(&ping_result);
    }
    if let Some(path) = &output {
        match save_json_output(&ping_result, path, JsonStyle::Pretty) {
            Ok(_) => {
                if !no_stdout {
                    tracing::info!("JSON output saved to {}", path.display());
                }
            },
            Err(e) => tracing::error!("Failed to save JSON output: {}", e),
        }
    }
    Ok(())
}
