use std::{net::IpAddr, path::PathBuf, time::Duration};

use crate::{cli::NeighborArgs, endpoint::Host, nei::NeighborDiscoveryResult, util::json::{save_json_output, JsonStyle}};
use anyhow::Result;

/// Run neighbor discovery (ARP for IPv4, NDP for IPv6)
pub async fn run(args: NeighborArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
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
    let nd_result: NeighborDiscoveryResult = match dst_host.ip {
        IpAddr::V4(ipv4) => {
            let recv_timeout = Duration::from_millis(args.timeout_ms);
            let mut arp_result = crate::nei::arp::send_arp(ipv4, &interface, recv_timeout).await?;
            match dst_host.hostname {
                Some(hostname) => {
                    arp_result.hostname = Some(hostname);
                },
                None => {
                    let timeout = Duration::from_millis(200);
                    arp_result.hostname = crate::dns::reverse_lookup(IpAddr::V4(ipv4), timeout).await;
                },
            }
            arp_result
        }
        IpAddr::V6(ipv6) => {
            let recv_timeout = Duration::from_millis(args.timeout_ms);
            let mut ndp_result = crate::nei::ndp::send_ndp(ipv6, &interface, recv_timeout).await?;
            match dst_host.hostname {
                Some(hostname) => {
                    ndp_result.hostname = Some(hostname);
                },
                None => {
                    let timeout = Duration::from_millis(200);
                    ndp_result.hostname = crate::dns::reverse_lookup(IpAddr::V6(ipv6), timeout).await;
                },
            }
            ndp_result
        }
    };
    if !no_stdout {
        crate::output::nei::print_neighbor_tree(&[nd_result.clone()]);
    }
    if let Some(path) = &output {
        match save_json_output(&nd_result, path, JsonStyle::Pretty) {
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
