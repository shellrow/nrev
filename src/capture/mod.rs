pub mod pcap;

/// Send through the IP stack on Linux loopback; AF_PACKET injection is capture-only there.
pub(crate) async fn send_packet(
    sender: &mut dyn nex::datalink::async_io::AsyncRawSender,
    interface: &netdev::Interface,
    packet: &[u8],
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if interface.is_loopback() {
        return send_loopback(packet);
    }
    let _ = interface;
    futures::future::poll_fn(|cx| sender.poll_send(cx, packet)).await
}

#[cfg(target_os = "linux")]
fn send_loopback(ethernet: &[u8]) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let packet = ethernet
        .get(14..)
        .filter(|packet| packet.len() >= 20)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "truncated raw packet")
        })?;
    let ipv6 = packet[0] >> 4 == 6;
    if ipv6 && packet.len() < 40 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "truncated IPv6 packet",
        ));
    }
    // SAFETY: socket receives constant, valid domain/type/protocol values.
    let raw = unsafe {
        libc::socket(
            if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the newly opened descriptor has exactly one owner.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is a valid initial representation of sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = if ipv6 {
        // SAFETY: storage has sufficient size and alignment for sockaddr_in6.
        let address = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_addr.s6_addr.copy_from_slice(&packet[24..40]);
        std::mem::size_of::<libc::sockaddr_in6>()
    } else {
        // SAFETY: storage has sufficient size and alignment for sockaddr_in.
        let address = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_addr.s_addr = u32::from_ne_bytes(packet[16..20].try_into().unwrap());
        std::mem::size_of::<libc::sockaddr_in>()
    };
    // IPPROTO_RAW includes the caller's IP header for both address families.
    // SAFETY: both buffers remain live for their supplied lengths; the descriptor is owned.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&storage as *const libc::sockaddr_storage).cast(),
            length as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
