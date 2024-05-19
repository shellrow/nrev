use clap::ArgMatches;
use nerum_core::dep;

pub fn check_dependencies(_arg: &ArgMatches) {
    let _ = dep::check_dependencies();
}
