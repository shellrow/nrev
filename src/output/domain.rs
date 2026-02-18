use crate::{
    dns::{Domain, DomainScanResult},
    output::tree_label,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use termtree::Tree;

fn split_and_sort_ips<I>(ips: I) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>)
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(x) => v4.push(x),
            IpAddr::V6(x) => v6.push(x),
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    (v4, v6)
}

/// Print the domain scan results in a tree structure.
pub fn print_domain_tree(base_domain: &Domain, res: &DomainScanResult) {
    let mut root = Tree::new(tree_label(format!(
        "Domain scan: {} (found: {}, elapsed: {:?})",
        base_domain.name,
        res.domains.len(),
        res.scan_time
    )));

    // base domain node
    let mut base_node = Tree::new(tree_label(&base_domain.name));

    let (base_v4, base_v6) = split_and_sort_ips(base_domain.ips.iter().copied());
    if !base_v4.is_empty() {
        let mut a = Tree::new(tree_label(format!("A ({})", base_v4.len())));
        for ip in base_v4 {
            a.push(Tree::new(ip.to_string()));
        }
        base_node.push(a);
    }
    if !base_v6.is_empty() {
        let mut aaaa = Tree::new(tree_label(format!("AAAA ({})", base_v6.len())));
        for ip in base_v6 {
            aaaa.push(Tree::new(ip.to_string()));
        }
        base_node.push(aaaa);
    }

    // Add subdomains under the base domain
    let mut doms = res.domains.clone();
    doms.sort_by(|a, b| a.name.cmp(&b.name));

    if doms.is_empty() {
        base_node.push(Tree::new(tree_label("No subdomains resolved")));
    }

    for d in doms {
        let mut node = Tree::new(d.name);
        let (v4, v6) = split_and_sort_ips(d.ips);

        if !v4.is_empty() {
            let mut a = Tree::new(tree_label(format!("A ({})", v4.len())));
            for ip in v4 {
                a.push(Tree::new(ip.to_string()));
            }
            node.push(a);
        }
        if !v6.is_empty() {
            let mut aaaa = Tree::new(tree_label(format!("AAAA ({})", v6.len())));
            for ip in v6 {
                aaaa.push(Tree::new(ip.to_string()));
            }
            node.push(aaaa);
        }

        base_node.push(node);
    }

    root.push(base_node);

    println!("{}", root);
}
