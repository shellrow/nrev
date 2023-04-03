#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod define;
mod db;
mod models;
mod commands;
use commands::{test_command, test_command_arg, test_command_return, test_command_result, test_command_async, exec_portscan, exec_hostscan, exec_ping, exec_traceroute, lookup_hostname, lookup_ipaddr, get_probe_log, get_probed_hosts, save_map_data, get_map_data};

fn main() {
  // Initialize DB
  match enmap_core::db::init_db() {
    Ok(raw_count) => println!("DB initialized. affected {} rows.", raw_count),
    Err(e) => println!("DB init failed: {}", e),
  }
  // Check if we are running as root
  if !enmap_core::process::privileged() {
    //enmap_core::process::restart_as_root();
  }
  // Run the Tauri application
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      test_command, 
      test_command_arg, 
      test_command_return, 
      test_command_result, 
      test_command_async, 
      exec_portscan, 
      exec_hostscan,
      exec_ping,
      exec_traceroute,
      lookup_hostname,
      lookup_ipaddr,
      get_probe_log,
      get_probed_hosts,
      save_map_data,
      get_map_data
      ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
