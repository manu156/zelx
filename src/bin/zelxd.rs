#![forbid(unsafe_code)]
use clap::Parser;
fn main() -> std::process::ExitCode {
    match zelx::daemon::run(zelx::daemon::Options::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zelxd: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
