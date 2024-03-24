use clap::ArgMatches;
use nerum_core::sys::dep;

pub fn check_dependencies(_arg: &ArgMatches) {
    dep::resolve_dependencies();
}
