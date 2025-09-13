use termtree::Tree;
use crate::nei::NeighborDiscoveryResult;

/// Print the neighbor discovery results in a tree structure.
pub fn print_neighbor_tree(entries: &[NeighborDiscoveryResult]) {
    if entries.is_empty() {
        println!("No neighbors found.");
        return;
    }

    let mut root = Tree::new("Neighbors".to_string());

    for e in entries {
        let title = match &e.hostname {
            Some(h) => format!("{} ({})", e.ip_addr, h),
            None => format!("{}", e.ip_addr),
        };
        let mut node = Tree::new(title);

        node.push(Tree::new(format!("MAC: {}", e.mac_addr.address())));

        if let Some(vendor) = &e.vendor {
            node.push(Tree::new(format!("Vendor: {}", vendor)));
        }

        node.push(Tree::new(format!("Interface: {} (idx={})", e.if_name, e.if_index)));

        node.push(Tree::new(format!("Protoco: {}", e.protocol.as_str().to_uppercase())));

        node.push(Tree::new(format!("RTT: {:.3}ms", e.rtt.as_secs_f64() * 1e3)));

        root.push(node);
    }

    println!("{}", root);
}
