#![forbid(unsafe_code)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};
fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        eprintln!("Usage: zelx-run command [arguments...]");
        return ExitCode::from(2);
    };
    let app = Path::new(&command).file_name().unwrap_or(&command);
    let error = Command::new(&command)
        .args(args)
        .env("ZELX_APP_ID", app)
        .exec();
    eprintln!(
        "zelx-run: {}: {error}",
        zelx::escaped(command.as_encoded_bytes())
    );
    ExitCode::from(if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}
