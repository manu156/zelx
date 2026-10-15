-- Compatible with the original Phase 0/1 schema. Do not renumber historical IDs.
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    target_glob TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    scope TEXT NOT NULL CHECK (scope IN ('ONCE', 'SESSION', 'ALWAYS')),
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_app ON rules (app_id, resource);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    app_id TEXT NOT NULL,
    app_instance TEXT NOT NULL,
    pid INTEGER NOT NULL,
    resource TEXT NOT NULL,
    target TEXT NOT NULL,
    decision TEXT NOT NULL,
    rule_id INTEGER,
    latency_us INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_app_ts ON events (app_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS revocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL,
    resource TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL
);
INSERT OR IGNORE INTO policy_state VALUES (1, 0);
CREATE TRIGGER IF NOT EXISTS rules_added AFTER INSERT ON rules BEGIN
    UPDATE policy_state SET revision = revision + 1;
END;
CREATE TRIGGER IF NOT EXISTS rules_removed AFTER DELETE ON rules BEGIN
    UPDATE policy_state SET revision = revision + 1;
END;
CREATE TRIGGER IF NOT EXISTS rules_changed AFTER UPDATE ON rules BEGIN
    UPDATE policy_state SET revision = revision + 1;
END;
PRAGMA user_version = 1;
