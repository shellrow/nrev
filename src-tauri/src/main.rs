#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod define;
mod option;
mod network;
mod validator;
mod result;
mod db;
mod db_models;
mod json_models;
mod models;
mod process;
mod sys;
mod dataset;
mod os;
mod scan;
mod commands;
use commands::{
  exec_portscan, 
  exec_hostscan, 
  exec_ping, 
  exec_traceroute, 
  lookup_hostname, 
  lookup_ipaddr, 
  get_probe_log, 
  get_probed_hosts, 
  save_map_data, 
  get_map_data, 
  get_top_probe_hist, 
  get_probe_stat,
  get_default_interface,
  get_port_scan_result,
  get_host_scan_result,
  get_ping_stat,
  get_trace_result,
  get_os_type,
  save_user_probe_data,
  save_user_group,
  save_user_tag
};

fn main() {
  // Check if we are running as root
  if !process::privileged() {
    process::restart_as_root();
  }
  // Run the Tauri application
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      exec_portscan, 
      exec_hostscan,
      exec_ping,
      exec_traceroute,
      lookup_hostname,
      lookup_ipaddr,
      get_probe_log,
      get_probed_hosts,
      save_map_data,
      get_map_data,
      get_top_probe_hist,
      get_probe_stat,
      get_default_interface,
      get_port_scan_result,
      get_host_scan_result,
      get_ping_stat,
      get_trace_result,
      get_os_type,
      save_user_probe_data,
      save_user_group,
      save_user_tag
      ])
      .setup(|app| {
        let app_handle = app.handle();
        sys::init(app_handle);
        Ok(())
      })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
