CREATE TABLE IF NOT EXISTS host (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL UNIQUE,
    hostname    TEXT,
    os_guess    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS port (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL DEFAULT 'open',
    service     TEXT,
    version     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS tried_module (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    port        INTEGER,
    module      TEXT NOT NULL,
    result      TEXT NOT NULL,
    detail      TEXT,
    tried_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_ip, port, module)
);

CREATE TABLE IF NOT EXISTS credential (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    service     TEXT,
    username    TEXT,
    password    TEXT,
    hash        TEXT,
    source      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS finding (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip       TEXT NOT NULL,
    port          INTEGER,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT,
    engagement_id TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    msf_id      TEXT NOT NULL UNIQUE,
    host_ip     TEXT NOT NULL,
    session_type TEXT NOT NULL,
    username    TEXT,
    opened_at   TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at   TEXT
);

-- One row per run. The dashboard's history and (future) After Action Report hang
-- off this entity. aar is reserved for the future model-generated report.
CREATE TABLE IF NOT EXISTS engagement (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at    TEXT,
    summary     TEXT,
    aar         TEXT
);

-- Every emitted telemetry event, persisted so a past engagement's feed and
-- modules panel can be replayed on reload. payload is JSON.
CREATE TABLE IF NOT EXISTS event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    type          TEXT NOT NULL,
    payload       TEXT,
    ts            REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_engagement ON event(engagement_id, id);
CREATE INDEX IF NOT EXISTS idx_finding_engagement ON finding(engagement_id);
