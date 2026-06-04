import json
import time
from typing import Any

import ollama

import config
import prompts
import tools.memory as memory
import tools.recon as recon


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
            "description": "Persist a record to the agent's operational memory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "One of: host, port, tried_module, credential, finding, session",
                    },
                    "data": {
                        "type": "object",
                        "description": "Field values matching the table schema for the given category",
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
    "memory_read":  lambda args: memory.read(args["category"], args["key"]),
    "memory_write": lambda args: memory.write(args["category"], args["data"]),
    "memory_query": lambda args: memory.query(args["category"], args.get("filters")),
    "complete":     lambda args: {"status": "complete", **args},
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
            return {"status": "error", "error": f"{target} is not in authorized scope"}

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
    system_prompt = prompts.build_system_prompt(tool_desc)

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
                "content": "Please call a tool to continue the engagement.",
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
