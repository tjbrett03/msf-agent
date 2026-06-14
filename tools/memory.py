import sqlite3
import json
from datetime import datetime
from pathlib import Path

import config


def _connect() -> sqlite3.Connection:
    db_path = Path(config.DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent readers while a writer holds the lock,
    # eliminating "database is locked" errors when multiple tool calls run
    # back-to-back in the same iteration.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns to tables that predate them, before schema.sql runs.

    CREATE TABLE IF NOT EXISTS cannot alter an existing table, and schema.sql now
    builds an index on finding.engagement_id, so on a pre-existing DB that column
    must be added here first or the index creation fails. On a fresh DB the
    finding table does not exist yet (PRAGMA returns nothing) and this is a no-op.
    """
    cols = [r[1] for r in conn.execute("PRAGMA table_info(finding)").fetchall()]
    if cols and "engagement_id" not in cols:
        conn.execute("ALTER TABLE finding ADD COLUMN engagement_id TEXT")
        conn.commit()


def _init_schema(conn: sqlite3.Connection) -> None:
    _migrate(conn)
    schema_path = Path(__file__).parent.parent / "db" / "schema.sql"
    conn.executescript(schema_path.read_text())
    conn.commit()


def get_connection() -> sqlite3.Connection:
    conn = _connect()
    _init_schema(conn)
    return conn


# --- tool functions ---

def read(category: str, key: str, filters: dict | None = None) -> dict:
    """
    Read all rows in a category matching the given key (usually an IP address).
    Optional filters dict adds extra AND conditions on top of the key lookup.

    category: "host", "port", "tried_module", "credential", "finding", "session"
    key: typically an IP address
    filters: optional dict of column=value pairs to narrow results
    """
    conn = get_connection()
    try:
        table_key_map = {
            "host":         ("host",         "ip"),
            "port":         ("port",         "host_ip"),
            "tried_module": ("tried_module", "host_ip"),
            "credential":   ("credential",   "host_ip"),
            "finding":      ("finding",      "host_ip"),
            "session":      ("session",      "host_ip"),
            "service_state":("service_state","host_ip"),
        }

        if category not in table_key_map:
            return {"status": "error", "error": f"unknown category: {category}"}

        table, key_col = table_key_map[category]
        extra = filters or {}

        conditions = [f"{key_col} = ?"]
        values: list = [key]
        for col, val in extra.items():
            conditions.append(f"{col} = ?")
            values.append(val)

        sql = f"SELECT * FROM {table} WHERE {' AND '.join(conditions)}"
        cur = conn.execute(sql, values)
        rows = [dict(r) for r in cur.fetchall()]
        return {"status": "ok", "category": category, "key": key, "rows": rows}

    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def write(category: str, data: dict | list) -> dict:
    """
    Insert or update a record.

    category: "host", "port", "tried_module", "credential", "finding", "session"
    data: dict of field values matching the table schema. For "port" category,
          data may also be a list of dicts to bulk-insert all ports in one call.
    """
    conn = get_connection()
    try:
        if category == "host":
            conn.execute(
                """
                INSERT INTO host (ip, hostname, os_guess)
                VALUES (:ip, :hostname, :os_guess)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname = excluded.hostname,
                    os_guess = excluded.os_guess
                """,
                {
                    "ip":       data.get("ip"),
                    "hostname": data.get("hostname"),
                    "os_guess": data.get("os_guess"),
                },
            )

        elif category == "port":
            items = data if isinstance(data, list) else [data]
            for item in items:
                conn.execute(
                    """
                    INSERT INTO port (host_ip, port, protocol, state, service, version)
                    VALUES (:host_ip, :port, :protocol, :state, :service, :version)
                    ON CONFLICT(host_ip, port, protocol) DO UPDATE SET
                        state   = excluded.state,
                        service = excluded.service,
                        version = excluded.version
                    """,
                    {
                        "host_ip":  item.get("host_ip"),
                        "port":     item.get("port"),
                        "protocol": item.get("protocol", "tcp"),
                        "state":    item.get("state", "open"),
                        "service":  item.get("service"),
                        "version":  item.get("version"),
                    },
                )

        elif category == "tried_module":
            conn.execute(
                """
                INSERT INTO tried_module (host_ip, port, module, result, detail)
                VALUES (:host_ip, :port, :module, :result, :detail)
                ON CONFLICT(host_ip, port, module) DO UPDATE SET
                    result = excluded.result,
                    detail = excluded.detail,
                    tried_at = datetime('now')
                """,
                {
                    "host_ip": data.get("host_ip"),
                    "port":    data.get("port"),
                    "module":  data.get("module"),
                    "result":  data.get("result"),
                    "detail":  data.get("detail"),
                },
            )

        elif category == "credential":
            conn.execute(
                """
                INSERT INTO credential (host_ip, service, username, password, hash, source)
                VALUES (:host_ip, :service, :username, :password, :hash, :source)
                """,
                {
                    "host_ip":  data.get("host_ip"),
                    "service":  data.get("service"),
                    "username": data.get("username"),
                    "password": data.get("password"),
                    "hash":     data.get("hash"),
                    "source":   data.get("source"),
                },
            )

        elif category == "finding":
            conn.execute(
                """
                INSERT INTO finding (host_ip, port, title, severity, evidence, engagement_id)
                VALUES (:host_ip, :port, :title, :severity, :evidence, :engagement_id)
                """,
                {
                    "host_ip":  data.get("host_ip"),
                    "port":     data.get("port"),
                    "title":    data.get("title"),
                    "severity": data.get("severity"),
                    "evidence": data.get("evidence"),
                    "engagement_id": data.get("engagement_id"),
                },
            )

        elif category == "session":
            conn.execute(
                """
                INSERT INTO session (msf_id, host_ip, session_type, username)
                VALUES (:msf_id, :host_ip, :session_type, :username)
                ON CONFLICT(msf_id) DO UPDATE SET
                    closed_at = :closed_at
                """,
                {
                    "msf_id":       data.get("msf_id"),
                    "host_ip":      data.get("host_ip"),
                    "session_type": data.get("session_type"),
                    "username":     data.get("username"),
                    "closed_at":    data.get("closed_at"),
                },
            )

        elif category == "service_state":
            # Status-transition writer: UPSERT on (host_ip, port). Unlike seeding,
            # this overwrites status/outcome/reason because a transition (attempted
            # -> exploited -> documented) is always meant to win over the prior row.
            conn.execute(
                """
                INSERT INTO service_state
                    (host_ip, port, service, status, outcome, reason, engagement_id)
                VALUES
                    (:host_ip, :port, :service, :status, :outcome, :reason, :engagement_id)
                ON CONFLICT(host_ip, port) DO UPDATE SET
                    status        = excluded.status,
                    outcome       = COALESCE(excluded.outcome, service_state.outcome),
                    reason        = COALESCE(excluded.reason, service_state.reason),
                    service       = COALESCE(excluded.service, service_state.service),
                    engagement_id = COALESCE(excluded.engagement_id, service_state.engagement_id),
                    updated_at    = datetime('now')
                """,
                {
                    "host_ip":  data.get("host_ip"),
                    "port":     data.get("port"),
                    "service":  data.get("service"),
                    "status":   data.get("status", "untried"),
                    "outcome":  data.get("outcome"),
                    "reason":   data.get("reason"),
                    "engagement_id": data.get("engagement_id"),
                },
            )

        else:
            return {"status": "error", "error": f"unknown category: {category}"}

        conn.commit()
        return {"status": "ok", "category": category, "written": True}

    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def create_engagement(engagement_id: str, target: str) -> dict:
    """Record the start of a run. INSERT OR IGNORE so a re-entrant call is safe."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO engagement (id, target, status) VALUES (?, ?, 'running')",
            (engagement_id, target),
        )
        conn.commit()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def finish_engagement(engagement_id: str, status: str, summary: str | None = None) -> dict:
    """Record the terminal state of a run (last writer wins). finish() is the
    authoritative caller; an explicit End relies on abort -> finish for status."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE engagement SET status = ?, summary = ?, ended_at = datetime('now') WHERE id = ?",
            (status, summary, engagement_id),
        )
        conn.commit()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def write_event(engagement_id: str, etype: str, payload, ts: float) -> dict:
    """Persist one telemetry event so a past engagement's feed/modules can be
    replayed on reload. payload is serialized to JSON."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO event (engagement_id, type, payload, ts) VALUES (?, ?, ?, ?)",
            (engagement_id, etype, json.dumps(payload), ts),
        )
        conn.commit()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def seed_service_state(host_ip: str, port: int, service: str | None,
                       engagement_id: str | None = None) -> dict:
    """Create an 'untried' service_state row only if one does not already exist.

    Called from the scan auto-write so every open port has a progress row. Uses
    INSERT OR IGNORE (not UPSERT) on purpose: a re-scan must never knock a service
    that is already 'exploited'/'documented' back to 'untried'. Status transitions
    go through write('service_state', ...) instead.
    """
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO service_state
                (host_ip, port, service, status, engagement_id)
            VALUES (?, ?, ?, 'untried', ?)
            """,
            (host_ip, port, service, engagement_id),
        )
        conn.commit()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


# Forward progress order. A service only ever moves rightward, so a later, weaker
# event (e.g. a second module 'attempted' on a port already 'exploited') cannot
# knock it back. 'skipped' sits beside 'attempted': a deliberate skip should not
# overwrite a real exploit, but should win over an untried row.
_STATUS_RANK = {"untried": 0, "skipped": 1, "attempted": 1, "exploited": 2, "documented": 3}


def advance_service_state(host_ip: str, port: int, status: str,
                          outcome: str | None = None, reason: str | None = None,
                          engagement_id: str | None = None) -> dict:
    """Move a service forward to `status`, never backward.

    The status column only changes if the new status outranks the stored one, so
    transitions are monotonic and Phase B can trust 'documented' to stick. Outcome
    and reason refresh only when the event actually advances (or ties) the status;
    a rank-ignored event (e.g. a duplicate module that errors on an already
    'documented' port) must not overwrite the meaningful outcome with its noise.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status FROM service_state WHERE host_ip = ? AND port = ?",
            (host_ip, port),
        ).fetchone()
        current = row["status"] if row else None
        current_rank = _STATUS_RANK.get(current, 0) if current else -1
        new_rank = _STATUS_RANK.get(status, 0)
        advancing = new_rank >= current_rank
        keep = current if (current and current_rank > new_rank) else status
        # Discard outcome/reason from an ignored backward event so they cannot
        # clobber the detail recorded when the service last moved forward.
        out = outcome if advancing else None
        rsn = reason if advancing else None
        conn.execute(
            """
            INSERT INTO service_state
                (host_ip, port, status, outcome, reason, engagement_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_ip, port) DO UPDATE SET
                status        = ?,
                outcome       = COALESCE(?, service_state.outcome),
                reason        = COALESCE(?, service_state.reason),
                engagement_id = COALESCE(?, service_state.engagement_id),
                updated_at    = datetime('now')
            """,
            (host_ip, port, status, out, rsn, engagement_id,
             keep, out, rsn, engagement_id),
        )
        conn.commit()
        return {"status": "ok", "service_status": keep}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def query(category: str, filters: dict | None = None) -> dict:
    """
    Query across a category with optional filters.

    Primarily used by the agent to check tried_module before attempting an exploit.
    filters: dict of column=value pairs to filter by (all ANDed together)
    """
    conn = get_connection()
    try:
        table_map = {
            "host":         "host",
            "port":         "port",
            "tried_module": "tried_module",
            "credential":   "credential",
            "finding":      "finding",
            "session":      "session",
            "service_state":"service_state",
        }

        if category not in table_map:
            return {"status": "error", "error": f"unknown category: {category}"}

        table = table_map[category]
        filters = filters or {}

        if filters:
            where_clause = " AND ".join(f"{k} = ?" for k in filters)
            values = list(filters.values())
            sql = f"SELECT * FROM {table} WHERE {where_clause}"
            cur = conn.execute(sql, values)
        else:
            cur = conn.execute(f"SELECT * FROM {table}")

        rows = [dict(r) for r in cur.fetchall()]
        return {"status": "ok", "category": category, "filters": filters, "rows": rows}

    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()
