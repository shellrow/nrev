// Const Define for nodemap-desktop frontend

// Protocol
const PROTOCOL_ICMPv4 = "ICMPv4";
const PROTOCOL_ICMPv6 = "ICMPv6";
const PROTOCOL_TCP = "TCP";
const PROTOCOL_UDP = "UDP";

// Port Option
const PORT_OPTION_DEFAULT = "default";
const PORT_OPTION_WELL_KNOWN = "well_known";
const PORT_OPTION_CUSTOM_LIST = "custom_list";

// Scan Type
const PORTSCAN_TYPE_TCP_SYN = "tcp_syn_scan";
const PORTSCAN_TYPE_TCP_CONNECT = "tcp_connect_scan";
const HOSTSCAN_TYPE_NETWORK = "network";
const HOSTSCAN_TYPE_CUSTOM_HOSTS = "custom_list";

export { 
    PROTOCOL_ICMPv4,
    PROTOCOL_ICMPv6,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PORT_OPTION_DEFAULT, 
    PORT_OPTION_WELL_KNOWN, 
    PORT_OPTION_CUSTOM_LIST,
    PORTSCAN_TYPE_TCP_SYN,
    PORTSCAN_TYPE_TCP_CONNECT,
    HOSTSCAN_TYPE_NETWORK,
    HOSTSCAN_TYPE_CUSTOM_HOSTS,
};
