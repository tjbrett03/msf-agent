import json
import time
from typing import Any

import ollama

import config
import prompts
import tools.exploit as exploit
import tools.intel as intel
import tools.memory as memory
import tools.recon as recon
import tools.sessions as sessions


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
            "description": "Read all records in a category for a given key (usually an IP address).",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session",
                    },
                    "key": {"type": "string", "description": "IP address to look up"},
                },
                "required": ["category", "key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_write",
            "description": "Persist a record to the agent's operational memory. data must be a single dict, not a string or list. Examples by category -- host: {\"ip\": \"1.2.3.4\", \"hostname\": \"target\", \"os_guess\": \"Linux\"} -- port: {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"protocol\": \"tcp\", \"state\": \"open\", \"service\": \"ftp\", \"version\": \"vsftpd 2.3.4\"} -- tried_module: {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"module\": \"exploit/unix/ftp/vsftpd_234_backdoor\", \"result\": \"ok\", \"detail\": \"session opened\"} -- finding: {\"host_ip\": \"1.2.3.4\", \"port\": 21, \"title\": \"vsftpd backdoor\", \"severity\": \"critical\", \"evidence\": \"root shell obtained\"}",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session",
                    },
                    "data": {
                        "type": "object",
                        "description": "A single dict of field values for the chosen category. Must be a dict, not a string or list.",
                    },
                },
                "required": ["category", "data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_query",
            "description": "Query a category with optional column filters. Use this to check tried_module before attempting an exploit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session",
                    },
                    "filters": {
                        "type": "object",
                        "description": "Optional dict of column=value pairs to filter results",
                    },
                },
                "required": ["category"],
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
                    "findings": {
                        "type": "array",
                        "description": "List of finding objects with host, title, severity, evidence fields",
                        "items": {"type": "object"},
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
    "memory_read":  lambda args: memory.read(args["category"], args["key"]),
    "memory_write": lambda args: memory.write(args["category"], args["data"]),
    "memory_query": lambda args: memory.query(args["category"], args.get("filters")),
    "run_module":   lambda args: exploit.run_module(
        args["host_ip"], args["port"], args["module"], args.get("options"),
    ),
    "list_sessions": lambda args: sessions.list_sessions(),
    "run_command":   lambda args: sessions.run_command(args["session_id"], args["command"]),
    "complete":      lambda args: {"status": "complete", **args},
}


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


def run(target: str) -> dict:
    """
    Run the agentic loop against target until complete() is called or limits hit.
    Returns the completion result dict.
    """
    if target not in config.AUTHORIZED_SCOPE:
        return {"status": "error", "error": f"{target} is not in authorized scope"}

    tool_desc = prompts.build_tool_descriptions(TOOL_SCHEMAS)
    system_prompt = prompts.build_system_prompt(tool_desc, target)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Pentest {target}. Call complete() when done."},
    ]

    client = ollama.Client(host=config.OLLAMA_HOST)
    start_time = time.time()
    iteration = 0

    while iteration < config.MAX_ITERATIONS:
        elapsed = time.time() - start_time
        if elapsed > config.MAX_DURATION:
            return {
                "status":  "timeout",
                "message": f"max duration {config.MAX_DURATION}s exceeded after {iteration} iterations",
            }

        iteration += 1
        print(f"[iter {iteration}] calling model...")

        try:
            response = client.chat(
                model=config.OLLAMA_MODEL,
                messages=messages,
                tools=TOOL_SCHEMAS,
            )
        except Exception as e:
            return {"status": "error", "error": f"ollama call failed: {e}"}

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

            print(f"[iter {iteration}] tool call: {tool_name}({tool_args})")
            result = _dispatch(tool_name, tool_args)
            print(f"[iter {iteration}] tool result: {result}")

            messages.append({
                "role":    "tool",
                "content": json.dumps(result),
            })

            if result.get("status") == "complete":
                return result

    return {
        "status":  "limit_reached",
        "message": f"max iterations {config.MAX_ITERATIONS} reached",
    }
