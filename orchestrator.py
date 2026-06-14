import json
import threading
import time
import uuid
from typing import Any

import ollama

import config
import prompts
import tools.exploit as exploit
import tools.intel as intel
import tools.memory as memory
import tools.recon as recon
import tools.sessions as sessions
from event_bus import bus


# Tool schemas sent to the model so it knows what to call and how.
# Ollama Python library requires the {"type": "function", "function": {...}} wrapper.
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "scan_ports",
            "description": "Run an nmap port scan against a target IP. Returns open ports with service and version info. Do not use -O (OS detection requires root). Use -sV for service version detection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target":    {"type": "string", "description": "IP address to scan"},
                    "ports":     {"type": "string", "description": "Port range, e.g. '1-1000' or '22,80,443'"},
                    "arguments": {"type": "string", "description": "Extra nmap flags, e.g. '-sV -O'"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cves",
            "description": "Query the NVD for CVEs matching a service name and version. Returns CVE IDs, descriptions, and CVSS scores sorted highest first. Call this after scan_ports to research each discovered service before attempting exploits.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string",  "description": "Service name, e.g. 'vsftpd', 'openssh', 'apache'"},
                    "version": {"type": "string",  "description": "Version string, e.g. '2.3.4', '7.4p1'"},
                },
                "required": ["service", "version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "searchsploit",
            "description": "Search the Exploit-DB for public exploits matching a query. Use to find Metasploit module names for a known CVE or service/version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search terms, e.g. 'vsftpd 2.3.4' or 'CVE-2011-2523'"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_read",
            "description": "Read records from the agent's operational memory. Pass key (an IP address) to fetch all records for that host. Pass filters to narrow results by any column. Use this to check tried_module before attempting an exploit: memory_read('tried_module', '1.2.3.4', {'module': 'exploit/...'}).",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session",
                    },
                    "key": {
                        "type": "string",
                        "description": "IP address to look up (required)",
                    },
                    "filters": {
                        "type": "object",
                        "description": "Optional dict of column=value pairs to narrow results, e.g. {\"module\": \"exploit/unix/ftp/vsftpd_234_backdoor\"}",
                    },
                },
                "required": ["category", "key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_write",
            "description": "Persist a record to the agent's operational memory. For the port category, data may be a list of port dicts to write all ports at once. Examples -- host: {\"ip\": \"1.2.3.4\", \"hostname\": \"target\", \"os_guess\": \"Linux\"} -- port (single): {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"protocol\": \"tcp\", \"state\": \"open\", \"service\": \"ftp\", \"version\": \"vsftpd 2.3.4\"} -- port (bulk): [{\"host_ip\": \"1.2.3.4\", \"port\": 21, ...}, {\"host_ip\": \"1.2.3.4\", \"port\": 22, ...}] -- tried_module: {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"module\": \"exploit/unix/ftp/vsftpd_234_backdoor\", \"result\": \"ok\", \"detail\": \"session opened\"}. Findings are NOT written here; the runtime records them automatically from real results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, session (findings are recorded automatically by the runtime, not written here)",
                    },
                    "data": {
                        "type": "object",
                        "description": "A dict of field values for the chosen category, or a list of dicts for the port category bulk insert.",
                    },
                },
                "required": ["category", "data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_module",
            "description": "Run a Metasploit exploit or auxiliary module against a target. Always call memory_query('tried_module') first to confirm the module has not already been tried on this host and port.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host_ip": {"type": "string",  "description": "Target IP address"},
                    "port":    {"type": "integer", "description": "Target port number"},
                    "module":  {"type": "string",  "description": "Metasploit module path, e.g. exploit/unix/ftp/vsftpd_234_backdoor"},
                    "options": {"type": "object",  "description": "Optional module option overrides"},
                },
                "required": ["host_ip", "port", "module"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "List all active Metasploit sessions. Call this after run_module reports session_opened=True to get the session ID.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command inside an active session and return the output. Use this for post-exploitation: id, whoami, uname -a, cat /etc/passwd, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string",  "description": "Session ID from list_sessions"},
                    "command":    {"type": "string",  "description": "Shell command to run"},
                },
                "required": ["session_id", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "complete",
            "description": "End the engagement. Call this when you have exhausted reasonable options or achieved your objectives.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Prose summary of the engagement",
                    },
                },
                "required": ["summary"],
            },
        },
    },
]

TOOL_MAP = {
    "scan_ports":   lambda args: recon.scan_ports(**args),
    "lookup_cves":  lambda args: intel.lookup_cves(args["service"], args["version"]),
    "searchsploit": lambda args: intel.searchsploit(args["query"]),
    "memory_read":  lambda args: memory.read(args["category"], args["key"], args.get("filters")),
    "memory_write": lambda args: _model_memory_write(args),
    # memory_query kept as an internal alias so orchestrator code and existing tests
    # that call it directly continue to work; the model only sees memory_read.
    "memory_query": lambda args: memory.query(args["category"], args.get("filters")),
    "run_module":   lambda args: exploit.run_module(
        args["host_ip"], args["port"], args["module"], args.get("options"),
    ),
    "list_sessions": lambda args: sessions.list_sessions(),
    "run_command":   lambda args: sessions.run_command(args["session_id"], args["command"]),
    "complete":      lambda args: {"status": "complete", **args},
}


def _model_memory_write(args: dict) -> dict:
    """memory_write tool, with findings blocked.

    The finding table is generated by the runtime from real results only. The
    model is not allowed to author findings because it hallucinated them (e.g. a
    'cracked the msfadmin hash' finding the credential table flatly contradicts).
    We return ok with a note so the model does not loop retrying.
    """
    if args.get("category") == "finding":
        return {
            "status": "ok",
            "note": "findings are recorded automatically from actual results; no manual finding write is needed",
        }
    return memory.write(args["category"], args["data"])


def _dispatch(tool_name: str, tool_args: dict) -> dict:
    """
    Execute a tool call and return a structured result. Never raises to the caller.
    Unknown tool names and missing required args are returned as error dicts.
    """
    if tool_name not in TOOL_MAP:
        return {"status": "error", "error": f"unknown tool: {tool_name}"}

    # Scope enforcement: every tool that touches the network must target an authorized IP.
    if tool_name == "scan_ports":
        target = tool_args.get("target", "")
        if target not in config.AUTHORIZED_SCOPE:
            return {"status": "error", "error": f"{target} is not in authorized scope -- authorized targets: {config.AUTHORIZED_SCOPE}"}

    if tool_name == "run_module":
        host_ip = tool_args.get("host_ip", "")
        port    = tool_args.get("port")
        module  = tool_args.get("module", "")

        if not host_ip:
            return {"status": "error", "error": "missing required field: host_ip"}

        if host_ip not in config.AUTHORIZED_SCOPE:
            return {"status": "error", "error": f"{host_ip} is not in authorized scope -- authorized targets: {config.AUTHORIZED_SCOPE}"}

        # Runtime guard: block the module even if the model ignores its memory check.
        check = memory.query("tried_module", {"host_ip": host_ip, "port": port, "module": module})
        if check.get("rows"):
            return {
                "status": "error",
                "error":  f"{module} already tried on {host_ip}:{port} -- see tried_module for result",
            }

        try:
            result = TOOL_MAP["run_module"](tool_args)
        except TypeError as e:
            return {"status": "error", "error": f"bad arguments for run_module: {e}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

        # Persist the attempt so the guard holds on future calls, even if the model forgets.
        memory.write("tried_module", {
            "host_ip": host_ip,
            "port":    port,
            "module":  module,
            "result":  result.get("status", "unknown"),
            "detail":  json.dumps(result),
        })
        return result

    try:
        return TOOL_MAP[tool_name](tool_args)
    except TypeError as e:
        # Missing or unexpected keyword arguments from the model
        return {"status": "error", "error": f"bad arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _normalize_scan_key(tool_args: dict) -> tuple[str, str]:
    """
    Return (target, normalized_port_range) for duplicate-scan detection.
    Strips the 'arguments' flag so scans differing only in nmap flags compare equal.
    Rounds port range end down to the nearest 1000 so '1-1000' and '1-1024' compare equal.
    """
    target = tool_args.get("target", "")
    ports  = str(tool_args.get("ports", ""))
    if "-" in ports:
        parts = ports.split("-", 1)
        try:
            end      = int(parts[1].strip())
            end_norm = (end // 1000) * 1000
            ports    = f"{parts[0].strip()}-{end_norm}"
        except ValueError:
            pass
    return target, ports


def _clear_sessions() -> None:
    """Kill any MSF sessions left over from a previous engagement."""
    result = sessions.list_sessions()
    if result.get("status") != "ok":
        return
    count = result.get("count", 0)
    if count > 0:
        print(f"[setup] clearing {count} pre-existing session(s)")
        for sid in result["sessions"]:
            sessions.close_session(sid)


def _clear_engagement_tables(target: str) -> None:
    """
    Delete all rows for target from every engagement table so each run starts
    from a clean slate. Stale tried_module or port data from a prior run would
    confuse the model into trying dead sessions or skipping already-tried services.
    """
    conn = memory.get_connection()
    try:
        # finding is intentionally excluded: findings are engagement-scoped now
        # and must persist across runs so prior engagements stay reviewable.
        for table in ("port", "tried_module", "credential", "session"):
            conn.execute(f"DELETE FROM {table} WHERE host_ip = ?", (target,))
        conn.execute("DELETE FROM host WHERE ip = ?", (target,))
        conn.commit()
        print(f"[setup] cleared engagement tables for {target}")
    except Exception as e:
        print(f"[setup] warning: could not clear tables: {e}")
    finally:
        conn.close()


_MAX_TOOL_RESULT_CHARS = 1000


def _truncate_result(result: dict) -> str:
    """
    Serialize result to JSON. If it exceeds the limit, truncate and append a
    marker so the model knows data was cut. Prevents repeated large tool results
    (port tables, CVE lists) from filling the context window across 50 iterations.
    """
    s = json.dumps(result)
    if len(s) <= _MAX_TOOL_RESULT_CHARS:
        return s
    return s[:_MAX_TOOL_RESULT_CHARS] + f"... [truncated, {len(s)} chars total]"


def _sudo_l_status(messages: list[dict]) -> str:
    """
    Scan the last 10 tool-role messages for evidence of a sudo -l result.
    Returns 'full_sudo' if (ALL) ALL or (ALL : ALL) was found in output,
    'partial' if sudo -l ran but no full-access entry was present,
    or 'not_run' if sudo -l has not been called yet.
    """
    for m in reversed(messages[-10:]):
        if m.get("role") != "tool":
            continue
        content = m.get("content", "")
        if '"command": "sudo -l"' not in content:
            continue
        if "(ALL) ALL" in content or "(ALL : ALL)" in content:
            return "full_sudo"
        return "partial"
    return "not_run"


def build_supervisor_directive(target: str, messages: list[dict]) -> str:
    """
    Inspect DB state and recent message history to produce a concise
    steering directive injected before every Ollama call. Rules are
    checked in strict priority order; the first match wins.
    """
    # Rule 1: a root shell is open -- nothing else matters.
    session_result = memory.query("session", {"host_ip": target})
    if session_result.get("status") == "ok":
        open_sessions = [
            r for r in session_result.get("rows", [])
            if r.get("closed_at") is None
        ]
        for row in open_sessions:
            is_root = (
                row.get("username") == "root"
                or "root" in (row.get("session_type") or "").lower()
            )
            if is_root:
                msf_id = row.get("msf_id", "?")
                return (
                    f"STOP EXPLOITING. You have a root shell on {target} "
                    f"(session {msf_id}). Run post-exploitation commands now: "
                    "whoami, id, uname -a, cat /etc/passwd, cat /etc/shadow. "
                    "Findings are recorded automatically; call complete() when done."
                )

    # Rule 2: a non-root shell is open -- escalate before trying new services.
    # The specific directive depends on how far along the escalation attempt is.
    if session_result.get("status") == "ok":
        open_sessions = [
            r for r in session_result.get("rows", [])
            if r.get("closed_at") is None
        ]
        if open_sessions:
            msf_id = open_sessions[0].get("msf_id", "?")
            sudo_status = _sudo_l_status(messages)
            if sudo_status == "full_sudo":
                return (
                    f"You already confirmed full sudo access on {target}. "
                    f"Run 'sudo id' in session {msf_id} right now to confirm root. "
                    "Then call complete()."
                )
            if sudo_status == "partial":
                return (
                    f"sudo -l ran but no full sudo rights found on {target} "
                    f"(session {msf_id}). "
                    "Check SUID binaries: find / -perm -4000 2>/dev/null "
                    "or check kernel version for local exploits."
                )
            return (
                f"You have a user shell on {target} (session {msf_id}). "
                "Attempt privilege escalation before trying new exploits. "
                "Try sudo -l first."
            )

    # Rule 3: known ports exist but at least one has no exploit attempt yet.
    ports_result  = memory.read("port", target)
    tried_result  = memory.query("tried_module", {"host_ip": target})
    if ports_result.get("status") == "ok" and ports_result.get("rows"):
        all_ports   = {r["port"] for r in ports_result["rows"]}
        tried_ports = {r["port"] for r in tried_result.get("rows", [])}
        untried     = sorted(all_ports - tried_ports)
        if untried:
            return (
                f"Untried services on {target}: ports {untried}. "
                "Do not call complete() until each has an attempt or a documented skip reason."
            )

    # Rule 4: model has scanned the same target twice in the last 6 messages.
    scan_count = 0
    for m in messages[-6:]:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls", []):
            fn = tc.get("function", {})
            if fn.get("name") != "scan_ports":
                continue
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if args.get("target") == target:
                scan_count += 1
    if scan_count >= 2:
        return (
            f"You have already scanned {target} twice. "
            "Port data is in memory. Do not scan again. "
            "Move to exploitation."
        )

    # Rule 5: no special condition.
    return "Continue the engagement."


# Cooperative abort flags keyed by engagement_id. The dashboard sets one via
# request_abort(); the loop checks it each iteration and exits cleanly, no hard kill.
_abort_requested: dict[str, bool] = {}


def request_abort(engagement_id: str) -> None:
    _abort_requested[engagement_id] = True


# Only one engagement may run at a time. run() calls _clear_sessions(), which
# kills every MSF session regardless of target, so a second concurrent run would
# tear down the first one's shell. The launcher claims this single slot before
# starting a run thread and releases it when the thread ends.
_engagement_lock = threading.Lock()
_active_engagement: dict[str, str] | None = None  # {"id":..., "target":...}


def claim_engagement(target: str, engagement_id: str) -> bool:
    """Atomically reserve the single engagement slot. False if one is running.

    The check and set happen under one lock so two near-simultaneous starts
    (a double-clicked button) cannot both win the slot.
    """
    global _active_engagement
    with _engagement_lock:
        if _active_engagement is not None:
            return False
        _active_engagement = {"id": engagement_id, "target": target}
        return True


def active_engagement() -> dict[str, str] | None:
    """A copy of the running engagement {id, target}, or None if idle."""
    with _engagement_lock:
        return dict(_active_engagement) if _active_engagement else None


def release_engagement(engagement_id: str) -> None:
    """Free the slot, but only if this engagement is the one still holding it."""
    global _active_engagement
    with _engagement_lock:
        if _active_engagement and _active_engagement["id"] == engagement_id:
            _active_engagement = None


def _prune_messages(messages: list[dict], cap: int) -> list[dict]:
    """Keep the system prompt plus a sliding window of the most recent messages.

    SQLite is the durable memory and build_supervisor_directive re-injects the
    current port/session/tried-module state on every call, so old turns are
    redundant. Dropping them keeps the context (and KV cache / VRAM) bounded
    instead of growing each iteration until inference crawls and wedges.
    """
    if len(messages) <= cap:
        return messages
    tail = messages[-(cap - 1):]
    # A 'tool' result must follow its assistant tool_calls message. If the window
    # opens on an orphaned tool result, drop leading tool messages so the model
    # never sees a dangling result with no matching call.
    while tail and tail[0].get("role") == "tool":
        tail = tail[1:]
    return messages[0:1] + tail


def _record_finding(finding: dict, emit, engagement_id: str | None = None) -> None:
    """Persist a finding to the DB and stream it to the dashboard.

    Stamps engagement_id so the finding is scoped to its run. Logs when the write
    is rejected, so a bad finding surfaces in the feed instead of vanishing the
    way a non-string evidence field silently did.
    """
    if engagement_id is not None:
        finding = {**finding, "engagement_id": engagement_id}
    res = memory.write("finding", finding)
    if res.get("status") != "ok":
        emit("log", {"message": f"finding write failed: {res.get('error')}"})
    emit("finding", finding)


# Enumeration sweep for a fresh root shell. Each step is
# (title, primary command, fallback command) -- fallbacks cover hosts where the
# primary tool is missing (Metasploitable 2 has ifconfig/netstat, not ip/ss).
_ROOT_ENUM_STEPS = [
    ("System: kernel (uname -a)",       "uname -a",       None),
    ("System: OS release (/etc/issue)", "cat /etc/issue", None),
    ("System: hostname",                "hostname",       None),
    ("Users (/etc/passwd)",             "cat /etc/passwd", None),
    ("Network: interfaces",             "ip addr",        "ifconfig -a"),
    ("Network: listening sockets",      "netstat -tlnp",  "ss -tlnp"),
    ("Processes (ps aux)",              "ps aux",         None),
    ("Privileges (sudo -n -l)",         "sudo -n -l",     None),
]


def _run_enum_cmd(sid: str, primary: str, fallback: str | None) -> str:
    """Run an enumeration command, falling back when the primary yields nothing."""
    out = (sessions.run_command(sid, primary).get("output") or "").strip()
    if not out and fallback:
        out = (sessions.run_command(sid, fallback).get("output") or "").strip()
    return out


def _enumerate_root(sid: str, target: str, emit, engagement_id: str | None = None) -> None:
    """Sweep a root shell and persist the loot.

    Done in the runtime, not delegated to the model. Each command output is
    stored as an info finding; /etc/shadow is captured as a finding and also
    parsed into the credential table (the model historically dumped it but never
    saved it, leaving the credential table empty).
    """
    for title, primary, fallback in _ROOT_ENUM_STEPS:
        out = _run_enum_cmd(sid, primary, fallback)
        if not out:
            continue
        _record_finding({
            "host_ip":  target,
            "port":     None,
            "title":    f"Enumeration -- {title}",
            "severity": "info",
            "evidence": out[:2000],
        }, emit, engagement_id)

    shadow = _run_enum_cmd(sid, "cat /etc/shadow", None)
    if shadow:
        _record_finding({
            "host_ip":  target,
            "port":     None,
            "title":    "Credentials -- /etc/shadow",
            "severity": "high",
            "evidence": shadow[:2000],
        }, emit, engagement_id)
        _persist_shadow_credentials(shadow, target, emit)


def _persist_shadow_credentials(shadow: str, target: str, emit) -> None:
    """Parse /etc/shadow lines into the credential table, skipping locked accounts."""
    count = 0
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, pwhash = parts[0].strip(), parts[1].strip()
        # Skip accounts with no crackable hash: locked (!/!!/* or a !-prefix) or
        # empty. Only real hashes are worth persisting as loot.
        if not username or not pwhash or pwhash in ("*", "!", "!!") or pwhash.startswith("!"):
            continue
        res = memory.write("credential", {
            "host_ip":  target,
            "service":  "shell",
            "username": username,
            "password": None,
            "hash":     pwhash,
            "source":   "/etc/shadow",
        })
        if res.get("status") == "ok":
            count += 1
        else:
            emit("log", {"message": f"credential write failed: {res.get('error')}"})
    if count:
        emit("log", {"message": f"persisted {count} credential hash(es) from /etc/shadow"})


def run(target: str, engagement_id: str | None = None) -> dict:
    """
    Run the agentic loop against target until complete() is called or limits hit.
    Returns the completion result dict. Emits live telemetry on the EventBus keyed
    by engagement_id so the dashboard can stream the run as it happens.
    """
    engagement_id = engagement_id or str(uuid.uuid4())
    # Persist the engagement up front so emit/finish always have a row to attach
    # events and the terminal status to, even on the scope-reject path below.
    memory.create_engagement(engagement_id, target)

    def emit(etype: str, payload: dict) -> None:
        bus.emit(etype, payload, engagement_id)
        # Persist every event so a past engagement's feed and modules can be
        # replayed on reload. Inference dominates the loop, so the per-event
        # write is negligible.
        memory.write_event(engagement_id, etype, payload, time.time())

    def finish(result: dict) -> dict:
        status = result.get("status")
        memory.finish_engagement(engagement_id, status, result.get("summary") or result.get("message"))
        emit("engagement_finished", {"target": target, "status": status})
        _abort_requested.pop(engagement_id, None)
        return result

    if target not in config.AUTHORIZED_SCOPE:
        return finish({"status": "error", "error": f"{target} is not in authorized scope"})

    emit("engagement_started", {"target": target})
    _clear_sessions()
    _clear_engagement_tables(target)

    tool_desc = prompts.build_tool_descriptions(TOOL_SCHEMAS)
    system_prompt = prompts.build_system_prompt(tool_desc, target)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Begin the engagement against {target}. Start by calling scan_ports to discover open services, then follow the workflow in your instructions."},
    ]

    client = ollama.Client(host=config.OLLAMA_HOST, timeout=config.OLLAMA_TIMEOUT)
    start_time = time.time()
    iteration = 0
    last_scan_key: tuple | None = None   # normalized (target, port_range) of last scan
    scan_counts: dict[str, int] = {}     # target -> number of scans performed this run
    ports_reported = False               # write open ports as findings only once per run

    while iteration < config.MAX_ITERATIONS:
        if _abort_requested.get(engagement_id):
            emit("log", {"message": "abort requested, stopping engagement"})
            return finish({"status": "aborted", "message": "engagement aborted by user"})

        elapsed = time.time() - start_time
        if elapsed > config.MAX_DURATION:
            return finish({
                "status":  "timeout",
                "message": f"max duration {config.MAX_DURATION}s exceeded after {iteration} iterations",
            })

        iteration += 1
        # Cap the in-context history before each call. State lives in SQLite and
        # the directive re-injects it, so dropping old turns keeps inference fast
        # and the KV cache bounded rather than growing every iteration.
        messages = _prune_messages(messages, config.CONTEXT_MAX_MESSAGES)
        directive = build_supervisor_directive(target, messages)
        print(f"[iter {iteration}] directive: {directive}")
        emit("log", {"message": f"iter {iteration} directive: {directive}"})

        try:
            response = client.chat(
                model=config.OLLAMA_MODEL,
                messages=messages + [{"role": "user", "content": directive}],
                tools=TOOL_SCHEMAS,
            )
        except Exception as e:
            # Includes the OLLAMA_TIMEOUT case: a stuck/runaway generation now
            # raises here instead of hanging the engagement forever.
            emit("log", {"message": f"ollama call failed: {e}"})
            return finish({"status": "error", "error": f"ollama call failed: {e}"})

        msg = response.message

        # Model returned a plain text response with no tool call. Treat it as a
        # reasoning step and keep looping; the model may call a tool next turn.
        if not msg.tool_calls:
            print(f"[iter {iteration}] model responded with text (no tool call)")
            messages.append({"role": "assistant", "content": msg.content or ""})
            # Nudge the model back onto tool use rather than letting it drift.
            messages.append({
                "role":    "user",
                "content": f"Please call a tool to continue the engagement against {target}.",
            })
            continue

        # Process all tool calls the model requested in this turn.
        messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
            {"function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in msg.tool_calls
        ]})

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            tool_args = tc.function.arguments
            if isinstance(tool_args, str):
                try:
                    tool_args = json.loads(tool_args)
                except json.JSONDecodeError:
                    tool_args = {}

            # Stuck detection for repeated scan_ports calls.
            if tool_name == "scan_ports":
                scan_target = tool_args.get("target", "")
                prior_count = scan_counts.get(scan_target, 0)

                if prior_count >= 2:
                    # Hard block: target has been scanned twice already.
                    block_msg = (
                        f"You have already scanned {target} twice in this engagement. "
                        "Do NOT scan again. Call memory_read('port', '"
                        f"{target}') to access the stored port data and move to exploitation."
                    )
                    messages.append({"role": "user", "content": block_msg})
                    result = {
                        "status": "error",
                        "error":  f"scan blocked: {scan_target} scanned {prior_count} times -- use memory_read to access port data",
                    }
                    print(f"[iter {iteration}] scan blocked ({prior_count} prior scans for {scan_target})")
                    messages.append({"role": "tool", "content": _truncate_result(result)})
                    continue

                scan_key = _normalize_scan_key(tool_args)
                if scan_key == last_scan_key:
                    messages.append({
                        "role":    "user",
                        "content": (
                            f"You already have port data for {target} from the previous scan. "
                            "Do not scan again. Use the data you already have and move to the next step."
                        ),
                    })
                last_scan_key = scan_key
                scan_counts[scan_target] = prior_count + 1

            print(f"[iter {iteration}] tool call: {tool_name}({tool_args})")
            emit("log", {"message": f"iter {iteration}: {tool_name}({json.dumps(tool_args)[:200]})"})
            if tool_name == "run_module":
                emit("module_started", {
                    "module":  tool_args.get("module"),
                    "host_ip": tool_args.get("host_ip"),
                    "port":    tool_args.get("port"),
                })

            result = _dispatch(tool_name, tool_args)
            print(f"[iter {iteration}] tool result: {result}")

            if tool_name == "run_module":
                emit("module_finished", {
                    "module": tool_args.get("module"),
                    "result": result.get("status"),
                    "detail": result.get("error") or result.get("session_id") or "",
                })
            # Record each open port as an informational finding (severity "info",
            # this app's informational tier) so the recon surface shows up in the
            # findings table, not just exploited services. Once per run, since the
            # re-scan guard already blocks repeat scans and these are not vulns.
            if tool_name == "scan_ports" and result.get("status") == "ok" and not ports_reported:
                # Persist ports in the runtime, not via the model. The supervisor
                # directive reads the port table to pick untried services, and with
                # context pruning we cannot rely on the model having written them.
                open_ports = result.get("open_ports", [])
                ports_for_db = [{**p, "host_ip": target} for p in open_ports]
                if ports_for_db:
                    memory.write("port", ports_for_db)

                for p in open_ports:
                    svc = p.get("service") or "unknown"
                    finding = {
                        "host_ip":  target,
                        "port":     p.get("port"),
                        "title":    f"Open port {p.get('port')}/{p.get('protocol', 'tcp')} {svc}".strip(),
                        "severity": "info",
                        "evidence": (f"{svc} {p.get('version', '')}").strip() or "open",
                    }
                    _record_finding(finding, emit, engagement_id)
                ports_reported = True

            emit("log", {"message": f"iter {iteration} result: {_truncate_result(result)[:200]}"})

            messages.append({
                "role":    "tool",
                "content": _truncate_result(result),
            })

            if result.get("status") == "complete":
                # Findings come from the runtime (real module results, session
                # detection, enumeration output) only. A model-supplied findings
                # list is intentionally ignored: it was a hallucination vector
                # (e.g. claiming a password hash was cracked when it never was).
                # The model's prose still lands in engagement.summary.
                return finish(result)

            # When a session opens, auto-detect root via 'id' and write to the
            # session table so the supervisor directive steers via Rule 1
            # (root shell) or Rule 2 (user shell) on the next iteration.
            if tool_name == "run_module" and result.get("session_opened"):
                sid = str(result.get("session_id", ""))
                # Give the shell time to stabilize; probing immediately returns empty output.
                time.sleep(2)
                id_result = sessions.run_command(sid, "id")
                if "uid=0" in id_result.get("output", ""):
                    username = "root"
                else:
                    whoami_result = sessions.run_command(sid, "whoami")
                    if "root" in whoami_result.get("output", ""):
                        username = "root"
                    else:
                        print(f"[session] warning: could not confirm username for sid={sid}")
                        username = "unknown"
                memory.write("session", {
                    "msf_id":       sid,
                    "host_ip":      target,
                    "session_type": "shell",
                    "username":     username,
                })
                print(f"[session] sid={sid} username={username}")

                # Record the breach as a finding right here, independent of any
                # memory_write('finding') the model may or may not make. The model
                # is unreliable about this, and without it a successful root
                # compromise still leaves the dashboard findings table empty.
                # Mirrors the session auto-write above; emit so it also lands live.
                module = tool_args.get("module", "unknown module")
                finding = {
                    "host_ip":  target,
                    "port":     tool_args.get("port"),
                    "title":    f"Shell session as {username} via {module}",
                    "severity": "critical" if username == "root" else "high",
                    "evidence": (id_result.get("output") or "").strip()[:500] or f"session {sid} opened",
                }
                _record_finding(finding, emit, engagement_id)

                # On a root shell, sweep the host in the runtime rather than
                # trusting the model to do post-exploitation. Persists each
                # command output as a finding and the /etc/shadow hashes as loot.
                if username == "root":
                    _enumerate_root(sid, target, emit, engagement_id)

    return finish({
        "status":  "limit_reached",
        "message": f"max iterations {config.MAX_ITERATIONS} reached",
    })
