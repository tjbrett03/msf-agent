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
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    port        INTEGER,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    evidence    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
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
