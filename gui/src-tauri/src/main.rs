#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod define;
mod db;
mod models;
mod commands;
use commands::{test_command, test_command_arg, test_command_return, test_command_result, test_command_async, exec_portscan, exec_hostscan, exec_ping, exec_traceroute, lookup_hostname, lookup_ipaddr};

fn main() {
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
      lookup_ipaddr
      ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
