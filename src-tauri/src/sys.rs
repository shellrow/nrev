use std::{fs, env};
use std::path::{PathBuf, Path};

#[cfg(target_os = "windows")]
pub fn get_os_type() -> String {
    "windows".to_owned()
}

#[cfg(target_os = "linux")]
pub fn get_os_type() -> String {
    "linux".to_owned()
}

#[cfg(target_os = "macos")]
pub fn get_os_type() -> String {
    "macos".to_owned()
}

pub fn init(handle: tauri::AppHandle) {
    crate::sys::copy_db_from_resource(handle);
}

pub fn copy_db_from_resource(handle: tauri::AppHandle) {
    let resource_path = handle.path_resolver()
    .resolve_resource(format!("resources/{}", crate::define::DB_NAME))
    .expect("failed to resolve resource");
    let mut path: PathBuf = env::current_exe().unwrap();
    path.pop();
    path.push(crate::define::DB_NAME);

    if resource_path.exists() && !path.exists() {
        match fs::copy(resource_path, path) {
            Ok(_) => println!("Database copied successfully"),
            Err(e) => println!("Error copying database: {}", e),
        }
    }
}

pub fn copy_db() {
    let mut src_path: PathBuf = env::current_exe().unwrap();
    src_path.pop();
    src_path.push(Path::new("resources").join(crate::define::DB_NAME));
    let mut dst_path: PathBuf = env::current_exe().unwrap();
    dst_path.pop();
    dst_path.push(crate::define::DB_NAME);
    
    if src_path.exists() && !dst_path.exists() {
        match fs::copy(src_path, dst_path) {
            Ok(_) => println!("Database copied successfully"),
            Err(e) => println!("Error copying database: {}", e),
        }
    }
}
