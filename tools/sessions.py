from pymetasploit3.msfrpc import MsfRpcClient, ShellSession

import config

_SENTINEL = "---CMD_DONE---"


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


def run_command(session_id: str | int, command: str, timeout: int = 30) -> dict:
    """
    Run a shell command in an open session and return its output.
    Uses a sentinel echo so we know exactly when output has finished.
    """
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


def close_session(session_id: str | int) -> dict:
    """Stop an active session."""
    try:
        client = _connect()
        session = client.sessions.session(str(session_id))
        session.stop()
        return {"status": "ok", "session_id": str(session_id), "closed": True}
    except Exception as e:
        return {"status": "error", "error": str(e)}
