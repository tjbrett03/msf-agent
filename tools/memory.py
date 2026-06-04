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
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    schema_path = Path(__file__).parent.parent / "db" / "schema.sql"
    conn.executescript(schema_path.read_text())
    conn.commit()


def get_connection() -> sqlite3.Connection:
    conn = _connect()
    _init_schema(conn)
    return conn


# --- tool functions ---

def read(category: str, key: str) -> dict:
    """
    Read all rows in a category matching the given key.

    category: "host", "port", "tried_module", "credential", "finding", "session"
    key: typically an IP address
    """
    try:
        conn = get_connection()
        rows = []

        if category == "host":
            cur = conn.execute("SELECT * FROM host WHERE ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        elif category == "port":
            cur = conn.execute("SELECT * FROM port WHERE host_ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        elif category == "tried_module":
            cur = conn.execute("SELECT * FROM tried_module WHERE host_ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        elif category == "credential":
            cur = conn.execute("SELECT * FROM credential WHERE host_ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        elif category == "finding":
            cur = conn.execute("SELECT * FROM finding WHERE host_ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        elif category == "session":
            cur = conn.execute("SELECT * FROM session WHERE host_ip = ?", (key,))
            rows = [dict(r) for r in cur.fetchall()]

        else:
            return {"status": "error", "error": f"unknown category: {category}"}

        conn.close()
        return {"status": "ok", "category": category, "key": key, "rows": rows}

    except Exception as e:
        return {"status": "error", "error": str(e)}


def write(category: str, data: dict) -> dict:
    """
    Insert or update a record.

    category: "host", "port", "tried_module", "credential", "finding", "session"
    data: dict of field values matching the table schema
    """
    try:
        conn = get_connection()

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
                    "host_ip":  data.get("host_ip"),
                    "port":     data.get("port"),
                    "protocol": data.get("protocol", "tcp"),
                    "state":    data.get("state", "open"),
                    "service":  data.get("service"),
                    "version":  data.get("version"),
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
                INSERT INTO finding (host_ip, port, title, severity, evidence)
                VALUES (:host_ip, :port, :title, :severity, :evidence)
                """,
                {
                    "host_ip":  data.get("host_ip"),
                    "port":     data.get("port"),
                    "title":    data.get("title"),
                    "severity": data.get("severity"),
                    "evidence": data.get("evidence"),
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

        else:
            return {"status": "error", "error": f"unknown category: {category}"}

        conn.commit()
        conn.close()
        return {"status": "ok", "category": category, "written": True}

    except Exception as e:
        return {"status": "error", "error": str(e)}


def query(category: str, filters: dict | None = None) -> dict:
    """
    Query across a category with optional filters.

    Primarily used by the agent to check tried_module before attempting an exploit.
    filters: dict of column=value pairs to filter by (all ANDed together)
    """
    try:
        conn = get_connection()

        table_map = {
            "host":         "host",
            "port":         "port",
            "tried_module": "tried_module",
            "credential":   "credential",
            "finding":      "finding",
            "session":      "session",
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
        conn.close()
        return {"status": "ok", "category": category, "filters": filters, "rows": rows}

    except Exception as e:
        return {"status": "error", "error": str(e)}
