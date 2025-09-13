use std::{path::PathBuf, time::Duration};

use crate::{cli::TraceArgs, endpoint::Host, protocol::Protocol, trace::{TraceSetting, Tracer}, util::json::{save_json_output, JsonStyle}};
use anyhow::Result;

/// Run traceroute
pub async fn run(args: TraceArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
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
    let mut trace_setting: TraceSetting = match args.proto.to_protocol() {
        Protocol::Udp => TraceSetting::udp_trace(&interface, &dst_host)?,
        _ => {
            anyhow::bail!("Unsupported protocol");
        }
    };
    trace_setting.dst_port = Some(args.port);
    trace_setting.hop_limit = args.max_hops;
    trace_setting.send_rate = Duration::from_millis(args.interval_ms);
    trace_setting.receive_timeout = Duration::from_millis(args.timeout_ms);

    let tracer = Tracer::new(trace_setting);
    tracing::info!("Trace route to {} with {}...", args.target, args.proto.as_str().to_uppercase());
    let trace_result = tracer.run().await?;
    tracing::info!("Trace complete.");
    if !no_stdout {
        crate::output::trace::print_trace_tree(&trace_result, dst_host);
    }
    if let Some(path) = &output {
        match save_json_output(&trace_result, path, JsonStyle::Pretty) {
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
