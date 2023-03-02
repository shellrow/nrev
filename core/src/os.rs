use std::collections::HashMap;
use netscan::os::TcpFingerprint;
use crate::model::TCPFingerprint;

fn search_latest_gen(map: HashMap<String, (u32, TCPFingerprint)>, point: u32) -> TCPFingerprint {
    let mut gen_list : Vec<String> = vec![];
    let mut fingerprints: Vec<TCPFingerprint> = vec![];
    for v in map.values() {
        if v.0 == point {
            gen_list.push(v.1.class.generation.to_string());
            fingerprints.push(v.1.clone());
        }
    }
    match gen_list.iter().max() {
        Some(gen) => {
            for f in fingerprints {
                if f.class.generation == gen.to_string() {
                    return f;
                }
            }
        },
        None => {},
    }
    match map.iter().max_by(|a, b| a.1.0.cmp(&b.1.0)).map(|(_k, v)| v){
        Some(v) => {
            return v.1.clone();
        },   
        None => {
            return TCPFingerprint::new()
        },
    }

}

pub fn verify_fingerprints(fingerprint: TcpFingerprint, fingerprint_db:Vec<TCPFingerprint>) -> TCPFingerprint {
    let mut map: HashMap<String, (u32, TCPFingerprint)> = HashMap::new();
    for f in fingerprint_db {
        let mut point: u32 = 0;
        let mut index: usize = 0;
        for sf in f.syn_fingerprints.clone() {
            if index < fingerprint.tcp_syn_ack_fingerprint.len() {
                if sf.tcp_window_size == fingerprint.tcp_syn_ack_fingerprint[index].tcp_window_size {
                    point += 1;
                }
                let mut opsions : Vec<String> = vec![];
                for option in &fingerprint.tcp_syn_ack_fingerprint[index].tcp_option_order {
                    opsions.push(option.name());
                }
                //let options = fingerprint.tcp_syn_ack_fingerprint[index].tcp_option_o
                if sf.tcp_options == opsions {
                    point += 4;
                }
            }
            index += 1;
        }
        if f.ecn_fingerprint.tcp_ecn_support == fingerprint.tcp_enc_fingerprint.tcp_ecn_support {
            point += 1;
        }
        if f.ecn_fingerprint.ip_df == fingerprint.tcp_enc_fingerprint.ip_df {
            point += 1;
        }
        if f.ecn_fingerprint.tcp_window_size == fingerprint.tcp_enc_fingerprint.tcp_window_size {
            point += 1;
        }
        let mut opsions : Vec<String> = vec![];
        if fingerprint.tcp_enc_fingerprint.tcp_option_order.len() > 0 {
            for option in &fingerprint.tcp_enc_fingerprint.tcp_option_order {
                opsions.push(option.name());
            }
            if f.ecn_fingerprint.tcp_options == opsions {
                point += 4;
            }
        }else{
            if fingerprint.tcp_syn_ack_fingerprint.len() > 0 {
                for option in &fingerprint.tcp_syn_ack_fingerprint[0].tcp_option_order {
                    opsions.push(option.name());
                }
                if f.ecn_fingerprint.tcp_options == opsions {
                    point += 4;
                }
            }
        }
        if point >= 14 {
            map.insert(f.clone().cpe, (point, f));
        }
    }
    match map.iter().max_by(|a, b| a.1.0.cmp(&b.1.0)).map(|(_k, v)| v){
        Some(v) => {
            return search_latest_gen(map.clone(), v.0);
        },   
        None => {
            return TCPFingerprint::new()
        },
    }
}
