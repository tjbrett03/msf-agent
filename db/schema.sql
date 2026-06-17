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

-- The trust split: a finding records who authored it and whether the runtime
-- confirmed it. source 'runtime' findings come from real tool results and are
-- ground truth (confirmed = 1); source 'model' findings are the model's own
-- observations/claims and stay unconfirmed (confirmed = 0) until the runtime
-- verifies them. The model may surface claims here but may not pass them off as
-- confirmed facts.
CREATE TABLE IF NOT EXISTS finding (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip       TEXT NOT NULL,
    port          INTEGER,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT,
    engagement_id TEXT,
    source        TEXT,
    confirmed     INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One verdict per service (host_ip, port): is it vulnerable, how bad, and which
-- CVEs back that call. Distinct from service_state (which tracks exploitation
-- progress); this is the assessment conclusion. cve_ids is a comma/JSON string.
CREATE TABLE IF NOT EXISTS service_assessment (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    port        INTEGER NOT NULL,
    vulnerable  INTEGER,
    severity    TEXT,
    cve_ids     TEXT,
    assessed_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_ip, port)
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

-- One row per discovered service (host_ip, port), tracking how far the engagement
-- has taken it. This is the durable progress record that survives context
-- pruning: the model's in-context history is trimmed on long runs, so "have we
-- dealt with this port yet" must live in SQLite, not the conversation. Phase B
-- (exploit-and-document-every-service) reads this to decide when a run is done.
--   status: untried -> attempted -> exploited / documented / skipped
--   outcome: short machine note (e.g. module name, 'root shell', 'no module')
--   reason:  why skipped, when status = skipped
-- Cleared per run alongside port/tried_module (it is live run state, not history).
CREATE TABLE IF NOT EXISTS service_state (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip       TEXT NOT NULL,
    port          INTEGER NOT NULL,
    service       TEXT,
    status        TEXT NOT NULL DEFAULT 'untried',
    outcome       TEXT,
    reason        TEXT,
    engagement_id TEXT,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_ip, port)
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
