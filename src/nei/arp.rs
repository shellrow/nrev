use anyhow::Result;
use netdev::Interface;
use nex::packet::{
    arp::ArpOperation,
    frame::{Frame, ParseOption},
};
use std::{net::{IpAddr, Ipv4Addr}, time::{Duration, Instant}};
use futures::stream::StreamExt;
use futures::future::poll_fn;
use nex::datalink::async_io::{async_channel, AsyncChannel};
use crate::nei::NeighborDiscoveryResult;

/// Send an ARP request to the specified IPv4 address on the given interface and wait for a reply.
pub async fn send_arp(ipv4_addr: Ipv4Addr, iface: &Interface, recv_timeout: Duration) -> Result<NeighborDiscoveryResult> {
    let next_hop = crate::util::ip::next_hop_ip(iface, IpAddr::V4(ipv4_addr))
        .ok_or_else(|| anyhow::anyhow!("No next hop found for {}", ipv4_addr))?;

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

    let arp_packet = crate::packet::arp::build_arp_packet(iface, next_hop);

    let start_time = Instant::now();

    match poll_fn(|cx| tx.poll_send(cx, &arp_packet)).await {
        Ok(_) => {
        },
        Err(e) => eprintln!("Failed to send packet: {}", e),
    }

    loop {
        match tokio::time::timeout(recv_timeout, rx.next()).await {
            Ok(Some(Ok(packet))) => {
                let frame = Frame::from_buf(&packet, ParseOption::default()).unwrap();
                match &frame.datalink {
                    Some(dlink) => {
                        if let Some(arp) = &dlink.arp {
                            if arp.operation == ArpOperation::Reply
                                && arp.sender_proto_addr == next_hop
                            {
                                let rtt = Instant::now().duration_since(start_time);
                                let ndp_result = NeighborDiscoveryResult {
                                    mac_addr: arp.sender_hw_addr,
                                    vendor: super::lookup_vendor(&arp.sender_hw_addr),
                                    ip_addr: IpAddr::V4(arp.sender_proto_addr),
                                    hostname: None,
                                    rtt,
                                    protocol: crate::protocol::Protocol::Arp,
                                    if_name: iface.name.clone(),
                                    if_friendly_name: iface.friendly_name.clone(),
                                    if_index: iface.index,
                                };
                                return Ok(ndp_result);
                            }
                        }
                    }
                    None => continue,
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
