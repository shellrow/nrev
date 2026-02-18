use netdev::MacAddr;
use std::net::IpAddr;
use termtree::Tree;

use crate::endpoint::{Host, NodeType};
use crate::probe::ProbeStatusKind;
use crate::trace::TraceResult;

/// Format a Duration as HH:MM:SS.mmm
fn fmt_dur(d: std::time::Duration) -> String {
    // HH:MM:SS.mmm
    let s = d.as_secs();
    let ms = d.subsec_millis();
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        ms
    )
}

/// Format an IP address with an optional hostname.
fn fmt_ip_host(ip: IpAddr, host: &Option<String>) -> String {
    if let Some(h) = host {
        format!("{} ({})", ip, h)
    } else {
        ip.to_string()
    }
}

/// Print the traceroute results in a tree structure.
pub fn print_trace_tree(tr: &TraceResult, target: Host) {
    if tr.nodes.is_empty() {
        println!(
            "Traceroute to {} - no hops (elapsed {})",
            fmt_ip_host(target.ip, &target.hostname),
            fmt_dur(tr.elapsed_time)
        );
        return;
    }

    // Check if the target was reached
    let reached = tr
        .nodes
        .iter()
        .any(|n| n.ip_addr == target.ip && matches!(n.probe_status.kind, ProbeStatusKind::Done));
    let mut root = if reached {
        Tree::new(format!(
            "Traceroute to {} - reached ({} hops, elapsed {}, proto {})",
            fmt_ip_host(target.ip, &target.hostname),
            tr.nodes.len(),
            fmt_dur(tr.elapsed_time),
            tr.protocol.as_str().to_uppercase()
        ))
    } else {
        Tree::new(format!(
            "Traceroute to {} - not reached ({} hops, elapsed {}, proto {})",
            fmt_ip_host(target.ip, &target.hostname),
            tr.nodes.len(),
            fmt_dur(tr.elapsed_time),
            tr.protocol.as_str().to_uppercase()
        ))
    };

    let mut nodes = tr.nodes.clone();
    nodes.sort_by(|a, b| a.seq.cmp(&b.seq));

    for n in nodes {
        match n.probe_status.kind {
            ProbeStatusKind::Done => {
                let mut hop_node = Tree::new(format!(
                    "#{} {}",
                    n.seq,
                    fmt_ip_host(n.ip_addr, &n.host_name)
                ));

                if n.mac_addr != MacAddr::zero() && n.node_type == NodeType::Gateway {
                    hop_node.push(Tree::new(format!("MAC: {}", n.mac_addr)));
                }
                hop_node.push(Tree::new(format!(
                    "RTT: {:.3}ms",
                    n.rtt.as_secs_f64() * 1000.0
                )));
                hop_node.push(Tree::new(format!("TTL: {}", n.ttl)));
                hop_node.push(Tree::new(format!("HOP: {}", n.hop)));
                hop_node.push(Tree::new(format!("Type: {}", n.node_type.name())));

                root.push(hop_node);
            }
            ProbeStatusKind::Timeout => {
                let hop_node = Tree::new(format!("#{} timed out", n.seq));
                root.push(hop_node);
            }
            _ => {
                let hop_node = Tree::new(format!("#{} unknown", n.seq));
                root.push(hop_node);
            }
        }
    }

    println!("{}", root);
}
