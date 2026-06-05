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


def _init_schema(conn: sqlite3.Connection) -> None:
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
        return {"status": "ok", "category": category, "written": True}

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
