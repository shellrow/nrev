use std::env;

pub fn restart_as_root(show_elevation_dialog: bool) {
    let args = env::args().collect::<Vec<String>>();
    let mut cmd = privilege::runas::Command::new(&env::current_exe().unwrap());
    cmd.gui(show_elevation_dialog);
    cmd.force_prompt(true);
    cmd.args(&args[1..]);
    println!("{}", cmd.run().expect("failed to execute"));
    std::process::exit(0);
}

pub fn privileged() -> bool {
    privilege::user::privileged()
}
