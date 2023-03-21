use std::{env, vec};
use std::path::{PathBuf};
use rusqlite::{Connection, Result, params};
use uuid::Uuid;
use crate::{define, option};
use crate::result::{PortScanResult, HostScanResult, PingStat, PingResult, TraceResult, Node};
use crate::model::{ProbeLog};

pub fn connect_db() -> Result<Connection,rusqlite::Error> {
    let mut path: PathBuf = env::current_exe().unwrap();
    path.pop();
    path.push(define::DB_NAME);
    let conn = Connection::open(path)?;
    Ok(conn)
}

pub fn init_db() -> Result<usize, rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let conn: Connection = match connect_db() {
        Ok(c)=> c, 
        Err(e) => return Err(e),
    };
    // NOTE
    // This DB is intended to store and search results and is not relational aware.
    // datetime(CURRENT_TIMESTAMP, 'localtime')
    // probe_result
    let sql: &str = "CREATE TABLE IF NOT EXISTS probe_result (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        probe_id TEXT NOT NULL,
        probe_type_id TEXT NOT NULL,
        probe_target_addr TEXT NOT NULL,
        probe_target_name TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        probe_option TEXT NULL,
        scan_time INTEGER NULL, 
        service_detection_time INTEGER NULL, 
        os_detection_time INTEGER NULL, 
        probe_time INTEGER NULL, 
        transmitted_count INTEGER NULL,
        received_count INTEGER NULL,
        min_value INTEGER NULL,
        avg_value INTEGER NULL,
        max_value INTEGER NULL,
        issued_at TEXT NOT NULL);";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // port_scan_result
    let sql: &str = "CREATE TABLE IF NOT EXISTS port_scan_result (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        probe_id TEXT NOT NULL,
                        socket_addr TEXT NOT NULL,
                        ip_addr TEXT NOT NULL,
                        host_name TEXT NOT NULL,
                        port_no INTEGER NOT NULL, 
                        port_status_id TEXT NOT NULL, 
                        protocol_id TEXT NOT NULL,
                        issued_at TEXT NOT NULL
                    );";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // host_scan_result
    let sql: &str = "CREATE TABLE IF NOT EXISTS host_scan_result (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        probe_id TEXT NOT NULL,
                        ip_addr TEXT NOT NULL,
                        host_name TEXT NOT NULL,
                        port_no INTEGER NOT NULL,
                        issued_at TEXT NOT NULL
                    );";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // ping_result
    let sql: &str = "CREATE TABLE IF NOT EXISTS ping_result (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        probe_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        ip_addr TEXT NOT NULL,
                        host_name TEXT NOT NULL,
                        port_no INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        ttl INTEGER NULL,
                        hop INTEGER NULL,
                        rtt INTEGER NULL,
                        issued_at TEXT NOT NULL
                    );";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // traceroute_result
    let sql: &str = "CREATE TABLE IF NOT EXISTS traceroute_result (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        probe_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        ip_addr TEXT NOT NULL,
                        host_name TEXT NOT NULL,
                        ttl INTEGER NULL,
                        hop INTEGER NULL,
                        rtt INTEGER NULL,
                        node_type TEXT NULL,
                        issued_at TEXT NOT NULL
                    );";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // probe_type
    let sql: &str = "CREATE TABLE IF NOT EXISTS probe_type (
            probe_type_id TEXT PRIMARY KEY,
            probe_type_name TEXT NULL 
        );";
    match conn.execute(sql, params![]){
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    // probe type records
    let sql: &str = "INSERT OR IGNORE INTO probe_type (probe_type_id, probe_type_name) VALUES (?1, ?2);";
    let params_1: &[&dyn rusqlite::ToSql] = params![option::CommandType::PortScan.id(),option::CommandType::PortScan.name()];
    let params_2: &[&dyn rusqlite::ToSql] = params![option::CommandType::HostScan.id(),option::CommandType::HostScan.name()];
    let params_3: &[&dyn rusqlite::ToSql] = params![option::CommandType::Ping.id(),option::CommandType::Ping.name()];
    let params_4: &[&dyn rusqlite::ToSql] = params![option::CommandType::Traceroute.id(),option::CommandType::Traceroute.name()];
    for params in vec![params_1,params_2,params_3,params_4] {
        match conn.execute(sql, params) {
            Ok(row_count) => {
                affected_row_count += row_count;
            },
            Err(e) => return Err(e),
        };
    }
    Ok(affected_row_count)
}

pub fn get_probe_id() -> String {
    let id = Uuid::new_v4();
    id.to_string().replace("-", "")
}

pub fn insert_port_scan_result(conn:&Connection, probe_id: String, scan_result: PortScanResult, option_value: String) -> Result<usize,rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let sql: &str = "INSERT INTO probe_result (
        probe_id, 
        probe_type_id,
        probe_target_addr,
        probe_target_name,
        protocol_id,
        probe_option,
        scan_time, 
        service_detection_time, 
        os_detection_time, 
        probe_time, 
        issued_at)  
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10, datetime(CURRENT_TIMESTAMP, 'localtime'));";
    let params_vec: &[&dyn rusqlite::ToSql] = params![
        probe_id,
        option::CommandType::PortScan.id(),
        scan_result.host.ip_addr,
        scan_result.host.host_name,
        option::Protocol::TCP.id(),
        option_value,
        scan_result.port_scan_time.as_millis() as u64,
        scan_result.service_detection_time.as_millis() as u64,
        scan_result.os_detection_time.as_millis() as u64,
        scan_result.total_scan_time.as_millis() as u64
    ];
    match conn.execute(sql, params_vec) {
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };

    for port in scan_result.ports.clone() {
        let sql: &str = "INSERT INTO port_scan_result (probe_id, socket_addr, ip_addr, host_name, port_no, port_status_id, protocol_id, issued_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,datetime(CURRENT_TIMESTAMP, 'localtime'));";
        let params_vec: &[&dyn rusqlite::ToSql] = params![
            probe_id,
            format!("{}:{}",scan_result.host.ip_addr, port.port_number),
            scan_result.host.ip_addr,
            scan_result.host.host_name,
            port.port_number,
            port.port_status,
            option::Protocol::TCP.id()
        ];   
        match conn.execute(sql, params_vec) {
            Ok(row_count) => {
                affected_row_count += row_count;
            },
            Err(e) => return Err(e),
        };
    }
    Ok(affected_row_count)
}

pub fn insert_host_scan_result(conn:&Connection, probe_id: String, scan_result: HostScanResult, option_value: String)  -> Result<usize,rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let sql: &str = "INSERT INTO probe_result (
        probe_id, 
        probe_type_id,
        probe_target_addr,
        probe_target_name,
        protocol_id,
        probe_option,
        scan_time, 
        probe_time, 
        issued_at)  
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,datetime(CURRENT_TIMESTAMP, 'localtime'));";
    let params_vec: &[&dyn rusqlite::ToSql] = params![
        probe_id,
        option::CommandType::HostScan.id(),
        String::new(),
        String::new(),
        scan_result.protocol.id(),
        option_value,
        scan_result.host_scan_time.as_millis() as u64,
        scan_result.total_scan_time.as_millis() as u64
    ];   
    match conn.execute(sql, params_vec) {
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    for host in scan_result.hosts {
        let sql: &str = "INSERT INTO host_scan_result (probe_id, ip_addr, host_name, port_no, issued_at)
        VALUES (?1,?2,?3,?4,datetime(CURRENT_TIMESTAMP, 'localtime'));";
        let params_vec: &[&dyn rusqlite::ToSql] = params![
            probe_id,
            host.ip_addr,
            host.host_name,
            scan_result.port_number
        ];   
        match conn.execute(sql, params_vec) {
            Ok(row_count) => {
                affected_row_count += row_count;
            },
            Err(e) => return Err(e),
        };
    }

    Ok(affected_row_count)
}

pub fn insert_ping_result(conn:&Connection, probe_id: String, ping_stat: PingStat, option_value: String)  -> Result<usize,rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    
    let ping_result: PingResult = ping_stat.ping_results[0].clone();
    let sql: &str = "INSERT INTO probe_result (
        probe_id, 
        probe_type_id,
        probe_target_addr,
        probe_target_name,
        protocol_id,
        probe_option, 
        probe_time, 
        min_value,
        avg_value,
        max_value,
        issued_at)  
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,datetime(CURRENT_TIMESTAMP, 'localtime'));";
    let params_vec: &[&dyn rusqlite::ToSql] = params![
        probe_id,
        option::CommandType::Ping.id(),
        ping_result.ip_addr.to_string(),
        ping_result.host_name,
        ping_result.protocol,
        option_value,
        ping_stat.probe_time / 1000,
        ping_stat.min / 1000,
        ping_stat.avg / 1000,
        ping_stat.max / 1000
    ];   
    match conn.execute(sql, params_vec) {
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    for ping in ping_stat.ping_results {
        let sql: &str = "INSERT INTO ping_result (probe_id, seq, ip_addr, host_name, port_no, status, ttl, hop, rtt, issued_at) 
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,datetime(CURRENT_TIMESTAMP, 'localtime'));";
        let params_vec: &[&dyn rusqlite::ToSql] = params![
            probe_id,
            ping.seq,
            ping.ip_addr.to_string(),
            ping.host_name,
            ping.port_number.unwrap_or(0),
            ping.status.name(),
            ping.ttl,
            ping.hop,
            ping.rtt / 1000
        ];   
        match conn.execute(sql, params_vec) {
            Ok(row_count) => {
                affected_row_count += row_count;
            },
            Err(e) => return Err(e),
        };
    }
    Ok(affected_row_count)
}

pub fn insert_trace_result(conn:&Connection, probe_id: String, trace_result: TraceResult, option_value: String)  -> Result<usize,rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let first_node: Node = trace_result.nodes[0].clone();
    let sql: &str = "INSERT INTO probe_result (
        probe_id, 
        probe_type_id,
        probe_target_addr,
        probe_target_name,
        protocol_id,
        probe_option, 
        probe_time, 
        issued_at)  
        VALUES (?1,?2,?3,?4,?5,?6,?7,datetime(CURRENT_TIMESTAMP, 'localtime'));";
    let params_vec: &[&dyn rusqlite::ToSql] = params![
        probe_id,
        option::CommandType::Traceroute.id(),
        first_node.ip_addr.to_string(),
        first_node.host_name,
        option::Protocol::UDP.id(),
        option_value,
        trace_result.probe_time / 1000
    ];   
    match conn.execute(sql, params_vec) {
        Ok(row_count) => {
            affected_row_count += row_count;
        },
        Err(e) => return Err(e),
    };
    for node in trace_result.nodes {
        let sql: &str = "INSERT INTO traceroute_result (probe_id, seq, ip_addr, host_name, ttl, hop, rtt, node_type, issued_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,datetime(CURRENT_TIMESTAMP, 'localtime'));";
        let params_vec: &[&dyn rusqlite::ToSql] = params![
            probe_id,
            node.seq,
            node.ip_addr.to_string(),
            node.host_name,
            node.ttl.unwrap_or(0),
            node.hop.unwrap_or(0),
            node.rtt.as_millis() as u64,
            node.node_type.name()
        ];   
        match conn.execute(sql, params_vec) {
            Ok(row_count) => {
                affected_row_count += row_count;
            },
            Err(e) => return Err(e),
        };
    }
    Ok(affected_row_count)
}

pub fn get_probe_result(target_host: String, probe_types: Vec<String>, start_date: String, end_date: String) -> Vec<ProbeLog> {
    let target_host = if crate::validator::is_valid_hostname(target_host.clone()) {target_host} else {String::from("%")};
    let mut results: Vec<ProbeLog> = vec![];
    let conn = connect_db().unwrap();
    let mut in_params: String = String::new();
    let mut pram_index: usize = 4;
    for _t in probe_types.clone() {
        pram_index += 1;
        if pram_index == 5 {
            in_params = format!("?{}", pram_index);
        }else{
            in_params = format!("{}, ?{}", in_params, pram_index);
        }
    }
    let mut sql: String = "SELECT A.id, A.probe_id, A.probe_type_id, B.probe_type_name, A.probe_target_addr, A.probe_target_name, A.protocol_id, A.probe_option, A.issued_at 
    FROM probe_result AS A INNER JOIN probe_type AS B ON A.probe_type_id = B.probe_type_id ".to_string();
    sql = format!("{} WHERE A.issued_at BETWEEN ?1 AND ?2 ", sql);
    sql = format!("{} AND (A.probe_target_addr LIKE ?3 OR A.probe_target_name LIKE ?4) ", sql);
    sql = format!("{} AND A.probe_type_id IN ({}) ", sql, in_params);
    sql = format!("{} ORDER BY A.issued_at DESC;", sql);
    let mut stmt = conn.prepare(sql.as_str()).unwrap();
    let mut params_vec: Vec<&dyn rusqlite::ToSql> = vec![
            &start_date,
            &end_date,
            &target_host,
            &target_host
        ]; 
    for t in &probe_types {
        params_vec.push(t);
    }
    let result_iter = stmt.query_map(&params_vec[..], |row| {
        Ok(ProbeLog {
            id: row.get(0).unwrap(), 
            probe_id: row.get(1).unwrap(), 
            probe_type_id: row.get(2).unwrap(), 
            probe_type_name: row.get(3).unwrap(), 
            probe_target_addr: row.get(4).unwrap(), 
            probe_target_name: row.get(5).unwrap(), 
            protocol_id: row.get(6).unwrap(), 
            probe_option: row.get(7).unwrap(), 
            issued_at: row.get(8).unwrap() 
        })
    }).unwrap();
    for result in result_iter {
        results.push(result.unwrap());
    }
    return results;
}
