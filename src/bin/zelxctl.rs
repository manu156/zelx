#![forbid(unsafe_code)]
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rusqlite::params;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};
use zelx::{
    db::{Backup, Database, Decision, Resource, Rule, Scope},
    escaped,
};

#[derive(Parser)]
#[command(about = "Zelx audit and policy management")]
struct Options {
    #[arg(long,env="ZELX_DB",default_value=zelx::DEFAULT_DB)]
    db: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Trace {
        #[arg(conflicts_with = "all")]
        app: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long,value_parser=parse_duration)]
        last: Option<i64>,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}
#[derive(ValueEnum, Clone)]
enum Permanent {
    Always,
}
#[derive(Subcommand)]
enum PolicyCommand {
    List {
        app: Option<String>,
    },
    Add {
        app: String,
        #[arg(value_enum)]
        decision: Decision,
        pattern: String,
        #[arg(value_enum)]
        scope: Permanent,
    },
    Revoke {
        app: String,
        #[arg(value_enum)]
        resource: Resource,
    },
    Export,
    Import {
        file: PathBuf,
    },
}
fn parse_duration(text: &str) -> std::result::Result<i64, String> {
    let split = text
        .len()
        .checked_sub(1)
        .ok_or("expected a duration such as 1h")?;
    let (digits, unit) = text.split_at_checked(split).ok_or("invalid duration")?;
    let factor = match unit {
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err("duration unit must be s, m, h, or d".into()),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("duration must be positive".into());
    }
    digits
        .parse::<i64>()
        .ok()
        .filter(|&n| n > 0)
        .and_then(|n| n.checked_mul(factor))
        .ok_or("duration is zero or too large".into())
}
fn audit_text(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    let value = row.get_ref(index)?;
    match value {
        // Legacy C records may contain raw filename bytes in a SQLite TEXT cell.
        // Escape the original bytes instead of rejecting or decoding them lossily.
        rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
            Ok(escaped(bytes))
        }
        _ => Err(rusqlite::Error::InvalidColumnType(
            index,
            index.to_string(),
            value.data_type(),
        )),
    }
}
fn run(options: Options) -> Result<()> {
    let readonly = matches!(
        options.command,
        Command::Trace { .. }
            | Command::Policy {
                command: PolicyCommand::List { .. } | PolicyCommand::Export
            }
    );
    let mut database = Database::open(&options.db, readonly)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    match options.command {
        Command::Trace { app, last, .. } => {
            let since = last
                .map(|duration| zelx::now_ms().saturating_sub(duration))
                .unwrap_or(0);
            let mut stmt = database.connection.prepare("SELECT ts,app_id,decision,resource,target FROM events WHERE (? IS NULL OR app_id=?) AND ts>=? ORDER BY ts,id")?;
            let rows = stmt.query_map(params![app, app, since], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    audit_text(r, 1)?,
                    audit_text(r, 2)?,
                    audit_text(r, 3)?,
                    audit_text(r, 4)?,
                ))
            })?;
            writeln!(output, "TIMESTAMP\tAPP\tDECISION\tRESOURCE\tTARGET")?;
            for row in rows {
                let (timestamp, app, decision, resource, target) = row?;
                let timestamp = chrono::DateTime::from_timestamp_millis(timestamp)
                    .context("invalid audit timestamp")?
                    .with_timezone(&chrono::Local);
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{}",
                    timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    app,
                    decision,
                    resource,
                    target
                )?;
            }
        }
        Command::Policy { command } => match command {
            PolicyCommand::List { app } => {
                writeln!(output, "ID\tAPP\tRESOURCE\tTARGET\tDECISION\tSCOPE")?;
                for rule in database
                    .rules(None, None)?
                    .into_iter()
                    .filter(|r| app.as_ref().is_none_or(|app| *app == r.app_id))
                {
                    writeln!(
                        output,
                        "{}\t{}\t{}\t{}\t{}\tALWAYS",
                        rule.id.unwrap_or(0),
                        escaped(rule.app_id.as_bytes()),
                        rule.resource.as_str(),
                        escaped(rule.target_glob.as_bytes()),
                        rule.decision.as_str()
                    )?;
                }
            }
            PolicyCommand::Add {
                app,
                decision,
                pattern,
                ..
            } => {
                let rule = Rule {
                    id: None,
                    app_id: app,
                    resource: Resource::Filesystem,
                    target_glob: pattern,
                    decision,
                    scope: Scope::Always,
                    created_at: 0,
                    created_by: "user".into(),
                };
                database.add_rule(&rule, "user")?;
            }
            PolicyCommand::Revoke { app, resource } => database.revoke(&app, resource)?,
            PolicyCommand::Export => {
                let backup = Backup {
                    version: 1,
                    rules: database.rules(None, None)?,
                };
                serde_json::to_writer_pretty(&mut output, &backup)?;
                writeln!(output)?;
            }
            PolicyCommand::Import { file } => {
                let mut bytes = Vec::new();
                File::open(file)?
                    .take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 8 * 1024 * 1024 {
                    bail!("policy import exceeds 8 MiB");
                }
                let backup = serde_json::from_slice(&bytes).context("invalid policy JSON")?;
                database.import(&backup)?;
            }
        },
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    let options = Options::parse();
    zelx::linux::private_umask();
    match run(options) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zelxctl: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duration_validation() {
        assert_eq!(parse_duration("1h").unwrap(), 3_600_000);
        for bad in [
            "",
            "0h",
            "-1h",
            "1x",
            "1hfoo",
            "999999999999999999999h",
            "1é",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
