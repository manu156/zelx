#![forbid(unsafe_code)]
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Filesystem,
    Network,
    Microphone,
    Camera,
    Clipboard,
    Screen,
    #[value(name = "process_signal")]
    ProcessSignal,
}
impl Resource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Microphone => "microphone",
            Self::Camera => "camera",
            Self::Clipboard => "clipboard",
            Self::Screen => "screen",
            Self::ProcessSignal => "process_signal",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
}
impl Decision {
    pub fn allowed(self) -> bool {
        self == Self::Allow
    }
    pub fn as_str(self) -> &'static str {
        if self.allowed() {
            "ALLOW"
        } else {
            "DENY"
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Scope {
    Once,
    Session,
    Always,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    #[serde(skip)]
    pub id: Option<i64>,
    pub app_id: String,
    pub resource: Resource,
    pub target_glob: String,
    pub decision: Decision,
    pub scope: Scope,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub created_by: String,
}
impl Rule {
    pub fn validate(&self) -> Result<()> {
        if self.app_id.is_empty() || self.app_id.len() >= 256 || self.app_id.contains('\0') {
            bail!("app_id must contain 1..255 bytes and no NUL");
        }
        if self.target_glob.is_empty()
            || self.target_glob.len() > 8192
            || self.target_glob.contains('\0')
        {
            bail!("target_glob must contain 1..8192 bytes and no NUL");
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Backup {
    pub version: u32,
    pub rules: Vec<Rule>,
}

pub struct AuditEvent<'a> {
    pub ts: i64,
    pub app: &'a str,
    pub pid: i32,
    pub target: &'a str,
    pub decision: &'a str,
    pub rule_id: Option<i64>,
    pub latency_us: i64,
}
pub struct Database {
    pub connection: Connection,
}
impl Database {
    pub fn open(path: &Path, readonly: bool) -> Result<Self> {
        if !readonly {
            // Ensure newly created databases are private without process-global umask changes.
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
            {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create private database {}", path.display()))
                }
            }
        }
        let flags = if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        // Never open/close an existing database outside SQLite: close() drops
        // process-wide POSIX locks held by other connections to that inode.
        let connection = Connection::open_with_flags(
            path,
            flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("open database {}", path.display()))?;
        let db = Self { connection };
        db.connection.busy_timeout(Duration::from_secs(1))?;
        let version: i64 = db
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
            bail!("unsupported database schema version {version}");
        }
        if !readonly {
            db.initialize()?;
        }
        Ok(db)
    }
    fn initialize(&self) -> Result<()> {
        self.connection.execute_batch(include_str!("schema.sql"))?;
        Ok(())
    }
    #[cfg(test)]
    pub fn memory() -> Self {
        let db = Self {
            connection: Connection::open_in_memory().unwrap(),
        };
        db.initialize().unwrap();
        db
    }
    pub fn add_rule(&self, rule: &Rule, creator: &str) -> Result<i64> {
        insert_rule(&self.connection, rule, creator)
    }
    pub fn revoke(&mut self, app: &str, resource: Resource) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM rules WHERE app_id=? AND resource=?",
            params![app, resource.as_str()],
        )?;
        tx.execute(
            "INSERT INTO revocations(app_id,resource) VALUES(?,?)",
            params![app, resource.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn rules(&self, app: Option<&str>, resource: Option<Resource>) -> Result<Vec<Rule>> {
        let mut statement = self.connection.prepare(
            "SELECT id,app_id,resource,target_glob,decision,scope,created_at,created_by FROM rules WHERE (? IS NULL OR app_id=? OR app_id='*') AND (? IS NULL OR resource=?) AND scope='ALWAYS' ORDER BY id")?;
        let resource = resource.map(Resource::as_str);
        let rows = statement.query_map(params![app, app, resource, resource], |row| {
            // Decode enums strictly: unknown values in a database must fail closed.
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        let mut rules = Vec::new();
        for row in rows {
            let (id, app_id, resource, target_glob, decision, scope, created_at, created_by) = row?;
            let rule = Rule {
                id: Some(id),
                app_id,
                resource: stored_enum(&resource)?,
                target_glob,
                decision: stored_enum(&decision)?,
                scope: stored_enum(&scope)?,
                created_at,
                created_by,
            };
            rule.validate()?;
            rules.push(rule);
        }
        Ok(rules)
    }
    pub fn import(&mut self, backup: &Backup) -> Result<()> {
        if backup.version != 1 {
            bail!("unsupported policy backup version");
        }
        for rule in &backup.rules {
            rule.validate()?;
            if rule.scope != Scope::Always {
                bail!("backup rules must have ALWAYS scope");
            }
        }
        // Dropping an uncommitted transaction rolls back partial imports.
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for rule in &backup.rules {
            insert_rule(&tx, rule, "import")?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn audit(&self, event: AuditEvent<'_>) -> Result<()> {
        self.connection.execute("INSERT INTO events(ts,app_id,app_instance,pid,resource,target,decision,rule_id,latency_us) VALUES(?,?,?,?,'filesystem',?,?,?,?)",
            params![event.ts,event.app,format!("{}:{}",event.app,event.pid),event.pid,event.target,event.decision,event.rule_id,event.latency_us])?;
        Ok(())
    }
}

fn insert_rule(connection: &Connection, rule: &Rule, creator: &str) -> Result<i64> {
    rule.validate()?;
    if rule.scope != Scope::Always {
        bail!("only ALWAYS rules belong in permanent storage");
    }
    connection.execute(
            "INSERT INTO rules(app_id,resource,target_glob,decision,scope,created_at,created_by) VALUES(?,?,?,?,'ALWAYS',?,?)",
            params![rule.app_id,rule.resource.as_str(),rule.target_glob,rule.decision.as_str(),crate::now_ms(),creator])?;
    Ok(connection.last_insert_rowid())
}

fn stored_enum<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    Ok(T::deserialize(serde::de::value::StrDeserializer::<
        serde::de::value::Error,
    >::new(text))?)
}
