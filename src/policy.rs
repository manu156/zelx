#![forbid(unsafe_code)]
use crate::db::{Database, Decision, Resource, Rule, Scope};
use anyhow::Result;
use lru::LruCache;
use std::{num::NonZeroUsize, path::Path};

pub fn path_under(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}
pub fn system_allowed(path: &str) -> bool {
    [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/fonts",
        "/etc/ssl/certs",
        "/proc/self",
        "/sys/class/dri",
    ]
    .iter()
    .any(|root| path_under(Path::new(path), Path::new(root)))
        || path == "/etc/timezone"
        || path.starts_with("/etc/ld.so.")
        || path.starts_with("/etc/locale")
}
#[derive(Debug)]
enum Token {
    Never,
    Literal(u8),
    Any,
    Star(bool),
    Class {
        negated: bool,
        bytes: Box<[bool; 256]>,
    },
}
fn named_class(name: &[u8], byte: u8) -> Option<bool> {
    Some(match name {
        b"alnum" => byte.is_ascii_alphanumeric(),
        b"alpha" => byte.is_ascii_alphabetic(),
        b"blank" => byte == b' ' || byte == b'\t',
        b"cntrl" => byte.is_ascii_control(),
        b"digit" => byte.is_ascii_digit(),
        b"graph" => byte.is_ascii_graphic(),
        b"lower" => byte.is_ascii_lowercase(),
        b"print" => byte.is_ascii_graphic() || byte == b' ',
        b"punct" => byte.is_ascii_punctuation(),
        b"space" => byte.is_ascii_whitespace() || byte == 0x0b,
        b"upper" => byte.is_ascii_uppercase(),
        b"xdigit" => byte.is_ascii_hexdigit(),
        _ => return None,
    })
}
fn bracket(pattern: &[u8], start: usize) -> Option<(Token, usize)> {
    let mut i = start + 1;
    let negated = matches!(pattern.get(i), Some(b'!' | b'^'));
    if negated {
        i += 1;
    }
    let mut bytes = Box::new([false; 256]);
    let mut items = 0;
    if pattern.get(i) == Some(&b']') {
        bytes[b']' as usize] = true;
        i += 1;
        items += 1;
    }
    while let Some(&byte) = pattern.get(i) {
        if byte == b']' && items > 0 {
            return Some((Token::Class { negated, bytes }, i + 1));
        }
        if byte == b'[' && pattern.get(i + 1) == Some(&b':') {
            let end = pattern.get(i + 2..)?.windows(2).position(|s| s == b":]")? + i + 2;
            let name = &pattern[i + 2..end];
            if named_class(name, 0).is_none() {
                // Unknown negated classes must not become an allow-everything set.
                return Some((Token::Never, end + 2));
            }
            for (b, matched) in bytes.iter_mut().enumerate() {
                *matched |= named_class(name, b as u8).unwrap_or(false);
            }
            i = end + 2;
            items += 1;
            continue;
        }
        let first = if byte == b'\\' {
            i += 1;
            *pattern.get(i)?
        } else {
            byte
        };
        i += 1;
        if pattern.get(i) == Some(&b'-') && pattern.get(i + 1).is_some_and(|&b| b != b']') {
            i += 1;
            if pattern.get(i) == Some(&b'\\') {
                i += 1;
            }
            let last = *pattern.get(i)?;
            i += 1;
            if first <= last {
                for b in first..=last {
                    bytes[b as usize] = true;
                }
            } else {
                return Some((Token::Never, i));
            }
        } else {
            bytes[first as usize] = true;
        }
        items += 1;
    }
    None
}
fn tokens(pattern: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        let byte = pattern[i];
        i += 1;
        match byte {
            b'*' => {
                let recursive = pattern.get(i) == Some(&b'*');
                while pattern.get(i) == Some(&b'*') {
                    i += 1;
                }
                tokens.push(Token::Star(recursive));
            }
            b'?' => tokens.push(Token::Any),
            b'[' => {
                if let Some((token, end)) = bracket(pattern, i - 1) {
                    tokens.push(token);
                    i = end;
                } else {
                    tokens.push(Token::Literal(byte));
                }
            }
            b'\\' if i < pattern.len() => {
                tokens.push(Token::Literal(pattern[i]));
                i += 1;
            }
            _ => tokens.push(Token::Literal(byte)),
        }
    }
    tokens
}
fn normalized_pattern(mut pattern: &str) -> &str {
    if !pattern.starts_with('/') {
        return pattern;
    }
    while let Some(prefix) = pattern.strip_suffix('/') {
        if prefix.is_empty() {
            return "/";
        }
        let escapes = prefix.bytes().rev().take_while(|&b| b == b'\\').count();
        // A quoted separator is still a separator. Preserve pairs of quoted
        // backslashes that belong to the directory's actual filename.
        pattern = if escapes % 2 == 1 {
            &prefix[..prefix.len() - 1]
        } else {
            prefix
        };
    }
    pattern
}

pub fn glob_match(pattern: &str, target: &str) -> bool {
    if pattern.len() > 8192 || target.len() >= 4096 {
        return false;
    }
    let pattern = normalized_pattern(pattern);
    let target = target.as_bytes();
    let mut current = vec![false; target.len() + 1];
    let mut next = current.clone();
    current[0] = true;
    for token in tokens(pattern.as_bytes()) {
        next.fill(false);
        if let Token::Star(recursive) = token {
            next[0] = current[0];
            for j in 1..=target.len() {
                next[j] = current[j] || next[j - 1] && (recursive || target[j - 1] != b'/');
            }
        } else {
            for (j, &byte) in target.iter().enumerate() {
                let matched = match &token {
                    Token::Never => false,
                    Token::Literal(literal) => byte == *literal,
                    Token::Any => byte != b'/',
                    Token::Class { negated, bytes } => {
                        byte != b'/' && (bytes[byte as usize] != *negated)
                    }
                    Token::Star(_) => unreachable!(),
                };
                next[j + 1] = current[j] && matched;
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    current[target.len()]
}
pub fn literal_pattern(path: &str) -> String {
    let mut escaped = String::new();
    for c in path.chars() {
        if "\\*?[]".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    pub rule_id: Option<i64>,
}
#[derive(Hash, PartialEq, Eq)]
struct Key {
    app: String,
    resource: Resource,
    target: String,
}

pub struct Policy {
    pub database: Database,
    sessions: Vec<SessionRule>,
    cache: LruCache<Key, Option<Evaluation>>,
    revision: i64,
    revocation: i64,
}

struct SessionRule {
    rule: Rule,
    // Revocations at or below this ID preceded the grant and cannot erase it.
    granted_after: i64,
}
impl Policy {
    pub fn new(database: Database) -> Self {
        Self {
            database,
            sessions: Vec::new(),
            cache: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            revision: -1,
            revocation: 0,
        }
    }
    fn synchronize(&mut self) -> Result<()> {
        let mut stmt = self
            .database
            .connection
            .prepare("SELECT id,app_id,resource FROM revocations WHERE id>? ORDER BY id")?;
        let changes = stmt.query_map([self.revocation], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for change in changes {
            let (id, app, resource) = change?;
            self.sessions.retain(|s| {
                s.granted_after >= id
                    || s.rule.app_id != app
                    || s.rule.resource.as_str() != resource
            });
            self.revocation = id;
            self.cache.clear();
        }
        let revision = self.database.connection.query_row(
            "SELECT revision FROM policy_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if self.revision != revision {
            self.revision = revision;
            self.cache.clear();
        }
        Ok(())
    }
    pub fn lookup(
        &mut self,
        app: &str,
        resource: Resource,
        target: &str,
    ) -> Result<Option<Evaluation>> {
        if resource == Resource::Filesystem && system_allowed(target) {
            return Ok(Some(Evaluation {
                decision: Decision::Allow,
                rule_id: None,
            }));
        }
        self.synchronize()?;
        let key = Key {
            app: app.into(),
            resource,
            target: target.into(),
        };
        if let Some(cached) = self.cache.get(&key) {
            return Ok(*cached);
        }
        let permanent = self.database.rules(Some(app), Some(resource))?;
        let best = permanent
            .iter()
            .chain(self.sessions.iter().map(|session| &session.rule))
            .filter(|r| {
                (r.app_id == app || r.app_id == "*")
                    && r.resource == resource
                    && glob_match(&r.target_glob, target)
            })
            .max_by_key(|r| {
                let pattern = normalized_pattern(&r.target_glob);
                (
                    r.app_id == app,
                    tokens(pattern.as_bytes())
                        .iter()
                        .all(|t| matches!(t, Token::Literal(_))),
                    pattern.len(),
                    r.decision == Decision::Deny,
                )
            })
            .map(|r| Evaluation {
                decision: r.decision,
                rule_id: r.id,
            });
        self.cache.put(key, best);
        Ok(best)
    }
    pub fn save(
        &mut self,
        app: &str,
        target: &str,
        decision: Decision,
        scope: Scope,
    ) -> Result<Option<i64>> {
        if scope == Scope::Once {
            return Ok(None);
        }
        let rule = Rule {
            id: None,
            app_id: app.into(),
            resource: Resource::Filesystem,
            target_glob: literal_pattern(target),
            decision,
            scope,
            created_at: crate::now_ms(),
            created_by: "user".into(),
        };
        rule.validate()?;
        self.cache.clear();
        match scope {
            Scope::Always => Ok(Some(self.database.add_rule(&rule, "user")?)),
            Scope::Session => {
                // This read defines the grant's ordering against concurrent
                // revoke transactions. A later revoke has a greater ID.
                let granted_after = self.database.connection.query_row(
                    "SELECT COALESCE(MAX(id),0) FROM revocations",
                    [],
                    |row| row.get(0),
                )?;
                self.sessions.push(SessionRule {
                    rule,
                    granted_after,
                });
                Ok(None)
            }
            Scope::Once => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(app: &str, pattern: &str, decision: Decision) -> Rule {
        Rule {
            id: None,
            app_id: app.into(),
            resource: Resource::Filesystem,
            target_glob: pattern.into(),
            decision,
            scope: Scope::Always,
            created_at: 0,
            created_by: "test".into(),
        }
    }
    #[test]
    fn glob_semantics_and_hostile_patterns() {
        for (pattern, target, expected) in [
            ("/h/**", "/h/a/b/c", true),
            ("/h/*.json", "/h/a.json", true),
            ("/h/*.json", "/h/sub/a.json", false),
            ("/h/file?.[ch]", "/h/file1.c", true),
            ("/h/[!0-9]", "/h/a", true),
            ("/h/[!0-9]", "/h/1", false),
            ("/h/[[:alpha:]][[:digit:]]", "/h/a1", true),
            ("/h/[[:space:]]", "/h/\u{000b}", true),
            ("/h/[![:space:]]", "/h/\u{000b}", false),
            ("/h/[![:unknown:]]*", "/h/anything", false),
            ("/h/[!z-a]*", "/h/anything", false),
            ("/h/\\*\\?\\[x\\]", "/h/*?[x]", true),
            ("/h/[", "/h/[", true),
            ("/h/path/", "/h/path/file", false),
            ("/h/path/", "/h/path", true),
            ("/h/path///", "/h/path", true),
            ("/h/path\\/", "/h/path", true),
            ("/h/dir\\\\/", "/h/dir\\", true),
            ("/", "/", true),
            ("*a*a*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaac", false),
        ] {
            assert_eq!(
                glob_match(pattern, target),
                expected,
                "{pattern} vs {target}"
            );
        }
        assert!(!path_under(
            Path::new("/home/ab/file"),
            Path::new("/home/a")
        ));
        assert!(system_allowed("/usr/lib/foo"));
        assert!(!system_allowed("/usr-malicious/foo"));
        assert!(!system_allowed("/etc/ld.soevil"));
    }
    #[test]
    fn precedence_scopes_and_literal_grants() {
        let mut p = Policy::new(Database::memory());
        p.database
            .add_rule(&rule("*", "/home/**", Decision::Deny), "test")
            .unwrap();
        p.database
            .add_rule(&rule("app", "/home/config/**", Decision::Allow), "test")
            .unwrap();
        let decision = |p: &mut Policy, app, target| {
            p.lookup(app, Resource::Filesystem, target)
                .unwrap()
                .unwrap()
                .decision
        };
        assert_eq!(decision(&mut p, "app", "/home/config/a"), Decision::Allow);
        assert_eq!(decision(&mut p, "other", "/home/config/a"), Decision::Deny);
        p.database
            .add_rule(&rule("app", "/home/config/exact", Decision::Deny), "test")
            .unwrap();
        p.database
            .add_rule(&rule("app", "/home/config/exact", Decision::Allow), "test")
            .unwrap();
        assert_eq!(
            decision(&mut p, "app", "/home/config/exact"),
            Decision::Deny
        );
        assert_eq!(decision(&mut p, "app", "/usr/lib/foo"), Decision::Allow);
        p.save("once", "/secret", Decision::Allow, Scope::Once)
            .unwrap();
        assert!(p
            .lookup("once", Resource::Filesystem, "/secret")
            .unwrap()
            .is_none());
        p.save("literal", "/secret*", Decision::Allow, Scope::Always)
            .unwrap();
        assert_eq!(decision(&mut p, "literal", "/secret*"), Decision::Allow);
        assert!(p
            .lookup("literal", Resource::Filesystem, "/secret-key")
            .unwrap()
            .is_none());
        p.save("session", "/secret", Decision::Allow, Scope::Session)
            .unwrap();
        assert_eq!(decision(&mut p, "session", "/secret"), Decision::Allow);
        p.database.revoke("session", Resource::Filesystem).unwrap();
        assert!(p
            .lookup("session", Resource::Filesystem, "/secret")
            .unwrap()
            .is_none());
        p.save("session", "/secret", Decision::Allow, Scope::Session)
            .unwrap();
        let mut restarted = Policy::new(p.database);
        assert!(restarted
            .lookup("session", Resource::Filesystem, "/secret")
            .unwrap()
            .is_none());
    }
    #[test]
    fn cache_bounds_and_invalidates_on_rule_mutation() {
        let mut p = Policy::new(Database::memory());
        p.database
            .add_rule(&rule("app", "/cache/**", Decision::Allow), "test")
            .unwrap();
        for i in 0..4100 {
            p.lookup("app", Resource::Filesystem, &format!("/cache/{i}"))
                .unwrap();
        }
        assert_eq!(p.cache.len(), 4096);
        p.database
            .add_rule(&rule("app", "/cache/4099", Decision::Deny), "test")
            .unwrap();
        assert_eq!(
            p.lookup("app", Resource::Filesystem, "/cache/4099")
                .unwrap()
                .unwrap()
                .decision,
            Decision::Deny
        );
    }
    #[test]
    fn external_revocations_invalidate_a_warm_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.db");
        let mut policy = Policy::new(Database::open(&path, false).unwrap());
        let mut writer = Database::open(&path, false).unwrap();
        for _ in 0..100 {
            writer
                .add_rule(&rule("app", "/protected/**", Decision::Allow), "test")
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    policy
                        .lookup("app", Resource::Filesystem, "/protected/secret")
                        .unwrap()
                        .unwrap()
                        .decision,
                    Decision::Allow
                );
            }
            writer.revoke("app", Resource::Filesystem).unwrap();
            assert!(policy
                .lookup("app", Resource::Filesystem, "/protected/secret")
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn session_grants_survive_older_revocations_but_not_newer_ones() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.db");
        let mut policy = Policy::new(Database::open(&path, false).unwrap());
        let mut writer = Database::open(&path, false).unwrap();
        assert!(policy
            .lookup("app", Resource::Filesystem, "/secret")
            .unwrap()
            .is_none());
        writer.revoke("app", Resource::Filesystem).unwrap();
        policy
            .save("app", "/secret", Decision::Allow, Scope::Session)
            .unwrap();
        assert_eq!(
            policy
                .lookup("app", Resource::Filesystem, "/secret")
                .unwrap()
                .unwrap()
                .decision,
            Decision::Allow
        );
        writer.revoke("app", Resource::Filesystem).unwrap();
        assert!(policy
            .lookup("app", Resource::Filesystem, "/secret")
            .unwrap()
            .is_none());
    }

    #[test]
    fn equivalent_directory_rules_keep_deny_precedence() {
        let mut policy = Policy::new(Database::memory());
        policy
            .database
            .add_rule(&rule("app", "/protected/", Decision::Allow), "test")
            .unwrap();
        policy
            .database
            .add_rule(&rule("app", "/protected", Decision::Deny), "test")
            .unwrap();
        assert_eq!(
            policy
                .lookup("app", Resource::Filesystem, "/protected")
                .unwrap()
                .unwrap()
                .decision,
            Decision::Deny
        );
    }
}
