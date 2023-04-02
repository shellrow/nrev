use std::env;
//use runas;

pub fn restart_as_root() {
    println!("check current exe and args...");
    println!("{}", env::current_exe().unwrap().display());
    println!("{}", env::args().collect::<Vec<String>>().join(" "));
    let args = env::args().collect::<Vec<String>>();
    let mut cmd = runas::Command::new(&env::current_exe().unwrap());
    cmd.gui(true);    
    cmd.force_prompt(true);
    cmd.args(&args[1..]);
    println!("{}",cmd.status().expect("failed to execute"));
    std::process::exit(0);
    /* println!(
        "Status: {}",
        runas::Command::new("id")
            .gui(true)
            .force_prompt(true)
            .status()
            .expect("failed to execute")
    ); */
}
