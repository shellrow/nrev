use anyhow::Result;
use netdev::Interface;
use nex::packet::{
    frame::{Frame, ParseOption},
    icmpv6::Icmpv6Type,
};
use std::{net::{IpAddr, Ipv6Addr}, time::{Duration, Instant}};
use futures::stream::StreamExt;
use futures::future::poll_fn;
use nex::datalink::async_io::{async_channel, AsyncChannel};
use crate::nei::NeighborDiscoveryResult;

/// Send an NDP (Neighbor Discovery Protocol) request to the specified IPv6 address on the given interface and wait for a reply.
pub async fn send_ndp(ipv6_addr: Ipv6Addr, iface: &Interface, recv_timeout: Duration) -> Result<NeighborDiscoveryResult> {
    let src_ip = iface
        .ipv6
        .iter()
        .map(|n| n.addr())
        .find(|ip| ip.segments()[0] == 0xfe80)
        .unwrap_or_else(|| iface.ipv6[0].addr());
    let next_hop = crate::util::ip::next_hop_ip(iface, IpAddr::V6(ipv6_addr))
        .ok_or_else(|| anyhow::anyhow!("No next hop found for {}", ipv6_addr))?;

    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(recv_timeout),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&iface, config)?
    else {
        unreachable!();
    };

    let arp_packet = crate::packet::ndp::build_ndp_packet(iface, next_hop);

    let start_time = Instant::now();
    
    match poll_fn(|cx| tx.poll_send(cx, &arp_packet)).await {
        Ok(_) => {
        },
        Err(e) => eprintln!("Failed to send packet: {}", e),
    }

    loop {
        match tokio::time::timeout(recv_timeout, rx.next()).await {
            Ok(Some(Ok(packet))) => {
                let mut parse_option = ParseOption::default();
                if iface.is_tun() {
                    parse_option.from_ip_packet = true;
                    parse_option.offset = if iface.is_loopback() { 14 } else { 0 };
                }

                if let Some(frame) = Frame::from_buf(&packet, parse_option) {
                    if let Some(ip_layer) = &frame.ip {
                        if let Some(icmpv6) = &ip_layer.icmpv6 {
                            if icmpv6.icmpv6_type == Icmpv6Type::NeighborAdvertisement {
                                if let Some(ipv6_hdr) = &ip_layer.ipv6 {
                                    if let Some(dlink) = &frame.datalink {
                                        if let Some(eth) = &dlink.ethernet {
                                            // eth.source is the MAC address of the device that replied
                                            if ipv6_hdr.destination == src_ip
                                                && ipv6_hdr.source == ipv6_addr
                                            {
                                                let rtt = Instant::now().duration_since(start_time);
                                                let ndp_result = NeighborDiscoveryResult {
                                                    mac_addr: eth.source,
                                                    vendor: super::lookup_vendor(&eth.source),
                                                    ip_addr: IpAddr::V6(ipv6_hdr.source),
                                                    hostname: None,
                                                    rtt,
                                                    protocol: crate::protocol::Protocol::Ndp,
                                                    if_name: iface.name.clone(),
                                                    if_friendly_name: iface.friendly_name.clone(),
                                                    if_index: iface.index,
                                                };
                                                return Ok(ndp_result);
                                                
                                            } else {
                                                eprintln!(
                                                    "Received NDP reply from unexpected source: {}",
                                                    ipv6_hdr.source
                                                );
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Some(Err(e))) => {
                tracing::error!("Failed to receive packet: {}", e);
                anyhow::bail!("Failed to receive packet: {}", e);
            },
            Ok(None) => {
                tracing::error!("Channel closed");
                anyhow::bail!("Channel closed");
            },
            Err(_) => {
                tracing::error!("Request timeout");
                anyhow::bail!("Request timeout");
            }
        }
    }
}
