// Rust IpAddr
export interface IpAddr {
  V4?: string;
  V6?: string;
}

// Rust Ipv4Addr
export interface Ipv4Addr {
  octets: number[];
}

// Rust Ipv6Addr
export interface Ipv6Addr {
  segments: number[];
}

export interface SocketAddr {
  ip: IpAddr;
  port: number;
}

export interface IpNet {
  addr: string;
  netmask: string;
  prefix_len: number;
}

export interface Device {
  ip_addr: string;
  mac_addr: string;
}
