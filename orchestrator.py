import json
import re
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
            "description": "Read records from the agent's operational memory. Pass key (an IP address) to fetch all records for that host. Pass filters to narrow results by any column. Use this to check tried_module before attempting an exploit: memory_read('tried_module', '1.2.3.4', {'module': 'exploit/...'}). Use service_assessment to read the runtime's automatic per-port CVE/severity verdicts when ranking what to exploit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session, service_state, service_assessment",
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
            "description": "Persist a record to the agent's operational memory. For the port category, data may be a list of port dicts to write all ports at once. Examples -- host: {\"ip\": \"1.2.3.4\", \"hostname\": \"target\", \"os_guess\": \"Linux\"} -- port (single): {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"protocol\": \"tcp\", \"state\": \"open\", \"service\": \"ftp\", \"version\": \"vsftpd 2.3.4\"} -- port (bulk): [{\"host_ip\": \"1.2.3.4\", \"port\": 21, ...}, {\"host_ip\": \"1.2.3.4\", \"port\": 22, ...}] -- tried_module: {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"module\": \"exploit/unix/ftp/vsftpd_234_backdoor\", \"result\": \"ok\", \"detail\": \"session opened\"} -- finding (your own observation): {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"title\": \"FTP allows anonymous login\", \"severity\": \"medium\", \"evidence\": \"...\"}. Findings you write are recorded as your own unconfirmed observations. Credentials CANNOT be written here; the runtime captures them automatically from real results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, finding, session. Credentials are captured automatically by the runtime and cannot be hand-written.",
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
            "description": "Run a Metasploit exploit or auxiliary module against a target. Always call memory_read('tried_module') first to confirm the module has not already been tried on this host and port.",
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
            "name": "enumerate",
            "description": "Convenience fallback that runs a fixed battery of enumeration commands in a session and returns their combined output. You should NORMALLY decide what to look at and issue your own run_command calls (that is where the real reasoning happens); use enumerate only when you want a quick scaffolded sweep. It does NOT read /etc/shadow -- dump that with an explicit run_command if you want it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID from list_sessions"},
                    "category":   {"type": "string", "description": "Which battery to run: one of system, users, network, processes, privileges, or all (default all)."},
                },
                "required": ["session_id"],
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
    "enumerate":     lambda args: sessions.enumerate_session(args["session_id"], args.get("category", "all")),
    "complete":      lambda args: {"status": "complete", **args},
}


def _model_memory_write(args: dict) -> dict:
    """memory_write tool, enforcing the trust split.

    The model may surface CLAIMS but may not author the FACTS the system acts on.
    Findings are allowed but stamped source='model'/confirmed=0 so a model
    observation can never masquerade as a runtime-confirmed fact. Credentials are
    blocked outright: they are captured automatically from real results, and a
    hand-written credential is exactly the hallucination that motivated this split
    (e.g. a 'cracked the msfadmin hash' claim the credential table contradicts).
    We return ok with a note on the blocked path so the model does not loop.
    """
    category = args.get("category")
    if category == "credential":
        return {
            "status": "ok",
            "note": "credentials are captured automatically by the runtime from real results and cannot be hand-written",
        }
    if category == "finding":
        # Copy, don't mutate the model's args: stamp provenance as an unconfirmed
        # model claim before persisting.
        data = {**args["data"], "source": "model", "confirmed": 0}
        return memory.write("finding", data)
    return memory.write(category, args["data"])


def _dispatch(tool_name: str, tool_args: dict) -> dict:
    """
    Execute a tool call and return a structured result. Never raises to the caller.
    Unknown tool names and missing required args are returned as error dicts.
    """
    if tool_name not in TOOL_MAP:
        return {"status": "error", "error": f"unknown tool: {tool_name}"}

    # Dedup CVE lookups within a run. The model, having had its context pruned,
    # re-requests the same (service, version) lookup; re-hitting NVD wastes a
    # round trip and refills the window with a payload it already saw. Serve the
    # cached result with a note instead. Only successful lookups are cached so a
    # transient NVD error can still be retried.
    if tool_name == "lookup_cves":
        service = tool_args.get("service")
        version = tool_args.get("version")
        if service is None or version is None:
            return {"status": "error", "error": "lookup_cves requires service and version"}
        key = (service, version)
        if key in _cve_cache:
            cached = dict(_cve_cache[key])
            cached["note"] = "cached from an earlier lookup this run; duplicate skipped"
            return cached
        result = intel.lookup_cves(service, version)
        if result.get("status") == "ok":
            _cve_cache[key] = result
        return result

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
        for table in ("port", "tried_module", "credential", "session", "service_state", "service_assessment"):
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
    Determine whether `sudo -l` has been run this engagement and, if so, whether
    it granted full sudo rights. Returns 'full_sudo' if (ALL) ALL or (ALL : ALL)
    was found in the output, 'partial' if sudo -l ran but no full-access entry
    was present, or 'not_run' if sudo -l has not been called yet.

    The fact that sudo -l ran is detected from the assistant tool_calls
    arguments (the call site), not the tool result: a tool-role message holds
    the command's OUTPUT, while what was actually invoked lives on the preceding
    assistant message's tool_calls. (sessions.run_command does happen to echo the
    command back into its result dict, but its exception path drops it, so the
    call site is the only reliable record that the command was issued.) The
    tool result is still consulted, but only to read the output that classifies
    full_sudo vs partial.
    """
    ran = False
    for m in reversed(messages[-12:]):
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {})
                if fn.get("name") != "run_command":
                    continue
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                cmd = (args.get("command") or "").strip()
                if cmd == "sudo -l" or cmd.startswith("sudo -l "):
                    ran = True
        elif role == "tool":
            content = m.get("content", "")
            if "sudo -l" not in content:
                continue
            if "(ALL) ALL" in content or "(ALL : ALL)" in content:
                return "full_sudo"
            ran = True
    return "partial" if ran else "not_run"


def _untried_services(target: str) -> list[str]:
    """
    Return the still-untried open ports as annotated strings, sorted by port.
    Sourced from service_state (the durable progress table the runtime seeds
    per open port on scan), so this fact survives context pruning even when the
    model has forgotten what it scanned. Where service_assessment carries a
    severity for a port, the string is annotated (e.g. "21 (critical)") so the
    model can rank what is worth its time. The runtime states the facts; the
    decision about which to pursue stays with the model.
    """
    svc_result = memory.query("service_state", {"host_ip": target})
    if svc_result.get("status") != "ok":
        return []
    untried_ports = sorted(
        r["port"] for r in svc_result.get("rows", []) if r.get("status") == "untried"
    )
    if not untried_ports:
        return []

    # Optional severity annotation from the vulnerability assessment table.
    severity_by_port: dict = {}
    assess_result = memory.query("service_assessment", {"host_ip": target})
    if assess_result.get("status") == "ok":
        for r in assess_result.get("rows", []):
            sev = r.get("severity")
            if sev:
                severity_by_port[r.get("port")] = sev

    annotated = []
    for port in untried_ports:
        sev = severity_by_port.get(port)
        annotated.append(f"{port} ({sev})" if sev else str(port))
    return annotated


def _loot_counts(target: str) -> tuple[int, int]:
    """
    Return (credential count, finding count) for target from durable memory.
    Re-injecting loot totals every turn is fact delivery that survives pruning,
    so a pivot/continue decision has real numbers behind it.
    """
    cred_rows = memory.query("credential", {"host_ip": target}).get("rows", [])
    finding_rows = memory.query("finding", {"host_ip": target}).get("rows", [])
    return len(cred_rows), len(finding_rows)


def build_supervisor_directive(target: str, messages: list[dict]) -> str:
    """
    Inspect DB state and recent message history to produce a concise
    situational-awareness directive injected before every Ollama call. Rules are
    checked in strict priority order; the first match wins.

    North star: the runtime delivers STATE and records truth; the model decides
    every action. Each rule states what is true and known (re-injected from
    SQLite so it survives context pruning) and hands the move to the model. The
    runtime does not issue orders here.
    """
    # Rules 1 and 2 both key off open sessions, so query once and share the list.
    session_result = memory.query("session", {"host_ip": target})
    open_sessions = (
        [r for r in session_result.get("rows", []) if r.get("closed_at") is None]
        if session_result.get("status") == "ok"
        else []
    )

    # Rule 1: a root shell is open. State the foothold and loot; the model
    # decides what to enumerate, loot, or whether to pivot.
    for row in open_sessions:
        is_root = (
            row.get("username") == "root"
            or "root" in (row.get("session_type") or "").lower()
        )
        if is_root:
            msf_id = row.get("msf_id", "?")
            creds, findings = _loot_counts(target)
            untried = _untried_services(target)
            untried_str = ", ".join(untried) if untried else "none"
            return (
                f"State: root shell on {target} (session {msf_id}). "
                f"Loot captured so far: {creds} credentials, {findings} findings. "
                f"Untried services remaining: {untried_str}. "
                "Decide what to enumerate, loot, or whether to pivot."
            )

    # Rule 2: a non-root shell is open. State the foothold, privesc progress
    # (derived from _sudo_l_status), loot, and what else is available, then leave
    # the escalate-or-pivot decision to the model.
    if open_sessions:
        msf_id = open_sessions[0].get("msf_id", "?")
        sudo_status = _sudo_l_status(messages)
        if sudo_status == "full_sudo":
            privesc = "sudo -l shows full sudo rights are available."
        elif sudo_status == "partial":
            privesc = "sudo -l ran and showed no full sudo rights."
        else:
            privesc = "sudo -l has not been run yet."
        creds, findings = _loot_counts(target)
        untried = _untried_services(target)
        untried_str = ", ".join(untried) if untried else "none"
        return (
            f"State: user shell on {target} (session {msf_id}); root not yet "
            f"achieved. Privesc status: {privesc} "
            f"Loot captured so far: {creds} credentials, {findings} findings. "
            f"Untried services remaining: {untried_str}. "
            "Decide whether to escalate or pivot."
        )

    # Rule 3: no open session, but discovered services have not been attempted.
    # State which (annotated with severity where known) so the model can rank
    # them; whether they are worth its time is the model's call.
    untried = _untried_services(target)
    if untried:
        return (
            f"State: no open session on {target}. "
            f"Vulnerable services not yet attempted: {', '.join(untried)}."
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
            f"State: {target} has already been scanned twice. "
            "Port data is in memory."
        )

    # Rule 5: no special condition.
    return "Continue the engagement."


# Cooperative abort flags keyed by engagement_id. The dashboard sets one via
# request_abort(); the loop checks it each iteration and exits cleanly, no hard kill.
_abort_requested: dict[str, bool] = {}

# Per-run cache of lookup_cves results, keyed by (service, version). Reset at the
# top of run(). Safe as module-level state because only one engagement runs at a
# time (see claim_engagement). See the dedup branch in _dispatch.
_cve_cache: dict[tuple, dict] = {}


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

    Runtime findings are ground truth, so they default to source='runtime' and
    confirmed=1 (the trust split): unlike a model claim, these come from real
    tool results. A caller that has already set source/confirmed wins.
    """
    if engagement_id is not None:
        finding = {**finding, "engagement_id": engagement_id}
    finding = {"source": "runtime", "confirmed": 1, **finding}
    res = memory.write("finding", finding)
    if res.get("status") != "ok":
        emit("log", {"message": f"finding write failed: {res.get('error')}"})
    emit("finding", finding)


# Loot patterns for _capture_loot. Compiled once at module load.
# A /etc/shadow-style line: a username, a $id$...$ crypt hash, then a colon. We
# match these specifically (not any colon-bearing line) because feeding ordinary
# command output to the credential parser would write bogus rows for lines like
# "Tasks: 5". A structured shadow line is the only run_command output treated as
# ground-truth credential loot.
_SHADOW_LINE_RE = re.compile(r"^[^:]+:\$[0-9a-z]+\$[^:]+:", re.MULTILINE)
# A PEM private key block. Non-greedy body so multiple blocks in one output each
# match rather than collapsing into one giant span. DOTALL so the body spans lines.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
# AWS access key id.
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
# Conservative inline-credential patterns: a URI with embedded user:password, and
# a password=... style assignment. Kept tight on purpose; loose patterns turn
# ordinary output into noise, and these go to the reviewable findings feed anyway.
_CONN_STRING_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+")
_PASSWORD_ASSIGN_RE = re.compile(r"(?i)\bpassword\s*[=:]\s*\S+")


def _capture_loot(output: str, target: str, emit, engagement_id: str | None = None) -> dict:
    """Scan command output for loot and persist it, no matter what the model did.

    The model decides where to look; this floor guarantees the catch is recorded.
    Shadow hashes are ground truth and go to the credential table; everything else
    (private keys, cloud keys, inline creds) is a regex guess, so it goes to the
    reviewable findings feed rather than the table the engagement acts on. Never
    raises: a loot-capture failure must not crash the loop.
    """
    if not output:
        return {"status": "ok", "credentials": 0, "findings": 0}

    cred_count = 0
    finding_count = 0
    try:
        # Shadow hashes: feed ONLY the matching lines to the existing parser, never
        # the whole output (it splits every line on ':' and would invent rows for
        # ordinary text like "Tasks: 5").
        matched = [ln for ln in output.splitlines() if _SHADOW_LINE_RE.match(ln)]
        if matched:
            _persist_shadow_credentials("\n".join(matched), target, emit)
            cred_count = len(matched)

        for block in _PRIVATE_KEY_RE.findall(output):
            _record_finding({
                "host_ip":  target,
                "port":     None,
                "title":    "Loot -- private key exposed in command output",
                "severity": "high",
                "evidence": block[:2000],
            }, emit, engagement_id)
            finding_count += 1

        for key in _AWS_KEY_RE.findall(output):
            _record_finding({
                "host_ip":  target,
                "port":     None,
                "title":    "Loot -- AWS access key exposed in command output",
                "severity": "high",
                "evidence": key,
            }, emit, engagement_id)
            finding_count += 1

        for match in _CONN_STRING_RE.findall(output):
            _record_finding({
                "host_ip":  target,
                "port":     None,
                "title":    "Loot -- inline credentials in connection string",
                "severity": "medium",
                "evidence": match[:500],
            }, emit, engagement_id)
            finding_count += 1

        for match in _PASSWORD_ASSIGN_RE.findall(output):
            _record_finding({
                "host_ip":  target,
                "port":     None,
                "title":    "Loot -- inline password assignment",
                "severity": "medium",
                "evidence": match[:500],
            }, emit, engagement_id)
            finding_count += 1
    except Exception as e:
        emit("log", {"message": f"loot capture failed: {e}"})

    return {"status": "ok", "credentials": cred_count, "findings": finding_count}


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


def _completion_blocked(target: str) -> dict | None:
    """Fact-check floor on complete(): the model owns the decision, almost always.

    The runtime refuses EXACTLY ONE case: a shell is open on the target AND no
    loot was captured this engagement. That is the one outcome the model cannot
    have meant -- it holds live access but recorded nothing actionable. Every
    other completion is the model's call, including documenting vulns without ever
    popping a shell (a legitimate result the user asked to allow).

    Loot is credentials (the runtime captures real ones from results) OR a finding
    titled "Loot -- ..." (the loot floor's secret catch). The auto open-port "info"
    findings and the "Shell session as ..." breach finding are NOT loot, so keying
    on credentials plus that title prefix excludes them correctly.

    Returns a refusal result dict the model can act on, or None to allow. Never
    raises: a query error is treated as "do not block" so a DB hiccup cannot trap
    the engagement.
    """
    try:
        sessions_result = memory.query("session", {"host_ip": target})
        open_shell = any(
            r.get("closed_at") is None for r in sessions_result.get("rows", [])
        )
        if not open_shell:
            return None

        creds = memory.query("credential", {"host_ip": target}).get("rows", [])
        if creds:
            return None

        findings = memory.query("finding", {"host_ip": target}).get("rows", [])
        if any((r.get("title") or "").startswith("Loot --") for r in findings):
            return None
    except Exception:
        # A DB hiccup must not strand the model on complete(); allow it through.
        return None

    return {
        "status": "error",
        "error": (
            f"Completion refused: you hold an open shell on {target} but have "
            "captured no loot this engagement. Enumerate the host and pull "
            "credentials or secrets (or record loot findings) before completing."
        ),
    }


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

    # Emit started before the scope check so the reject path below still produces
    # a balanced started/finished pair (finish emits engagement_finished); a lone
    # engagement_finished with no preceding start confuses the dashboard.
    emit("engagement_started", {"target": target})

    if target not in config.AUTHORIZED_SCOPE:
        return finish({"status": "error", "error": f"{target} is not in authorized scope"})

    _clear_sessions()
    _clear_engagement_tables(target)
    # Fresh CVE lookup cache per run. Only one engagement runs at a time (the
    # concurrency guard enforces it), so a module-level cache cannot bleed between
    # concurrent runs; resetting here keeps stale results from a prior run out.
    _cve_cache.clear()

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
                    # Hard block: target has been scanned twice already. The
                    # steering is folded into the tool result rather than emitted
                    # as a separate user message, which would otherwise land
                    # between the assistant tool_calls and this tool result and
                    # malform the chat template.
                    result = {
                        "status": "error",
                        "error":  (
                            f"scan blocked: {scan_target} scanned {prior_count} times. "
                            f"Do NOT scan again. Call memory_read('port', '{target}') to "
                            "access the stored port data and move to exploitation."
                        ),
                    }
                    print(f"[iter {iteration}] scan blocked ({prior_count} prior scans for {scan_target})")
                    messages.append({"role": "tool", "content": _truncate_result(result)})
                    continue

                scan_key = _normalize_scan_key(tool_args)
                if scan_key == last_scan_key:
                    # Identical re-scan: block it instead of just warning, so the
                    # scan does not actually run. Steering is folded into the tool
                    # result (see the hard-block note above) rather than emitted as
                    # a separate user message.
                    result = {
                        "status": "error",
                        "error":  (
                            f"scan blocked: you already have port data for {target} from "
                            "the previous scan. Do not scan again. Use the data you have and "
                            "move to the next step."
                        ),
                    }
                    print(f"[iter {iteration}] duplicate scan blocked ({scan_target})")
                    messages.append({"role": "tool", "content": _truncate_result(result)})
                    continue
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

            # Loot capture floor: scan every successful run_command or enumerate
            # output for credentials and secrets in the runtime, so loot is recorded
            # no matter where the model chose to look or whether it acts on what it
            # found. enumerate_session returns its combined battery output in
            # result["output"], so the floor catches anything that sweep surfaced.
            if tool_name in ("run_command", "enumerate") and result.get("status") == "ok":
                _capture_loot(result.get("output", ""), target, emit, engagement_id)

            if tool_name == "run_module":
                emit("module_finished", {
                    "module": tool_args.get("module"),
                    "result": result.get("status"),
                    "detail": result.get("error") or result.get("session_id") or "",
                })
                # Advance this service to 'attempted'. Forward-only, so a follow-up
                # module on a port already 'exploited' will not regress it. The
                # 'exploited' transition happens in the session_opened block below.
                mod_port = tool_args.get("port")
                if mod_port is not None:
                    memory.advance_service_state(
                        target, mod_port, "attempted",
                        outcome=f"{tool_args.get('module', '?')}: {result.get('status', '?')}",
                        engagement_id=engagement_id,
                    )
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

                # Seed one 'untried' progress row per open port. seed_service_state
                # is INSERT-OR-IGNORE, so re-seeding on a re-scan never regresses a
                # port we have already exploited. The supervisor directive reads
                # these rows to pick the next untried service, durably across pruning.
                for p in open_ports:
                    memory.seed_service_state(target, p.get("port"), p.get("service"), engagement_id)

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

                # Documentation axis: assess every open port for known CVEs at
                # scan time, in the runtime, so documentation is exhaustive and
                # complete before the model could ever finish. This is fact-
                # gathering (record truth), not a decision: a port is assessed
                # whether or not it is later exploited. The lookup goes through
                # _dispatch so it shares the per-run CVE cache (a redundant model
                # lookup will not re-hit NVD). One port's failure must not abort
                # the rest, so each port is assessed in its own try/except.
                for p in open_ports:
                    port_no = p.get("port")
                    service = p.get("service")
                    try:
                        if not service:
                            # No service banner means nothing to look up, but the
                            # row is still written so every open port is documented.
                            vulnerable, severity, cve_ids = 0, None, None
                        else:
                            cve = _dispatch("lookup_cves", {
                                "service": service,
                                "version": p.get("version") or "",
                            })
                            cves = cve.get("cves", []) if cve.get("status") == "ok" else []
                            if cves:
                                # cves is sorted by cvss_score descending, so the
                                # first entry is the most severe.
                                vulnerable = 1
                                severity   = cves[0].get("severity")
                                cve_ids     = ",".join(
                                    c.get("cve_id", "") for c in cves[:10]
                                )
                            else:
                                # Lookup succeeded with no CVEs, or errored: either
                                # way we have no vuln evidence. A transient NVD
                                # error must not abort documenting the rest.
                                vulnerable, severity, cve_ids = 0, None, None

                        memory.write("service_assessment", {
                            "host_ip":    target,
                            "port":       port_no,
                            "vulnerable": vulnerable,
                            "severity":   severity,
                            "cve_ids":    cve_ids,
                        })
                        emit("log", {"message": (
                            f"assessed {service or 'unknown'} on port {port_no}: "
                            f"vulnerable={vulnerable} severity={severity}"
                        )})
                    except Exception as e:
                        emit("log", {"message": (
                            f"assessment of port {port_no} failed: {e}"
                        )})
                ports_reported = True

            # Completion fact-check floor, BEFORE the tool-result append. If the
            # floor refuses, swap the refusal in as `result` so the model sees the
            # reason as its tool result and the loop continues; the complete() exit
            # below is then naturally skipped (result is no longer "complete").
            if result.get("status") == "complete":
                blocked = _completion_blocked(target)
                if blocked is not None:
                    result = blocked
                    emit("log", {"message": f"completion refused: open shell, no loot on {target}"})

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
                sid        = str(result.get("session_id", ""))
                shell_port = tool_args.get("port")
                module     = tool_args.get("module", "unknown module")

                # A freshly opened backdoor shell is frequently not ready to take
                # commands for a second or two. Probing too early gets the first
                # writes silently dropped, after which every read times out and
                # root can never be confirmed (this stalled a whole run). Warm the
                # shell until it round-trips a command before relying on it.
                warm = sessions.warm_up(sid)

                if not warm.get("ready"):
                    # Shell never became usable. Close it so it cannot drive an
                    # endless privesc loop (the directive keys off the open-session
                    # table), record the attempt, and move on. Deliberately write
                    # NO session row for an unusable shell.
                    sessions.close_session(sid)
                    emit("log", {"message": f"session {sid} opened but never responded; closed it"})
                    if shell_port is not None:
                        memory.advance_service_state(
                            target, shell_port, "exploited",
                            outcome=f"unresponsive shell via {module}",
                            engagement_id=engagement_id,
                        )
                    _record_finding({
                        "host_ip":  target,
                        "port":     shell_port,
                        "title":    f"Shell via {module} opened but was unresponsive",
                        "severity": "high",
                        "evidence": (warm.get("error") or "shell did not respond to commands")[:500],
                    }, emit, engagement_id)
                else:
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

                    # The service that popped the shell is now 'exploited'. Forward-
                    # only, so the prior 'attempted' write does not hold it back.
                    if shell_port is not None:
                        memory.advance_service_state(
                            target, shell_port, "exploited",
                            outcome=f"{username} shell via {module}",
                            engagement_id=engagement_id,
                        )

                    # Record the breach as a finding right here, independent of any
                    # memory_write('finding') the model may or may not make. Without
                    # it a successful compromise leaves the findings table empty.
                    _record_finding({
                        "host_ip":  target,
                        "port":     shell_port,
                        "title":    f"Shell session as {username} via {module}",
                        "severity": "critical" if username == "root" else "high",
                        "evidence": (id_result.get("output") or "").strip()[:500] or f"session {sid} opened",
                    }, emit, engagement_id)

                    # Shell opened AND its breach finding is recorded, so this
                    # service is written up. Post-exploitation enumeration is now
                    # model-driven (the model issues its own run_command calls and
                    # the loot floor captures anything in the output); the runtime
                    # no longer sweeps the host here. 'documented' is the terminal
                    # state Phase B reads to decide the run is complete.
                    if shell_port is not None:
                        memory.advance_service_state(
                            target, shell_port, "documented", engagement_id=engagement_id,
                        )

    return finish({
        "status":  "limit_reached",
        "message": f"max iterations {config.MAX_ITERATIONS} reached",
    })
