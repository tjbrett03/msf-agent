# MSF-Agent

An autonomous penetration testing agent driven by a local LLM. A hand-rolled
agentic loop (no LangChain, no agent frameworks) reasons over a target, calls
real tools (nmap, Metasploit, CVE intel), exploits what it finds, performs
post-exploitation, and documents the results, all streamed live to a web
dashboard.

It runs entirely on local infrastructure. The model is Qwen2.5 14B served by
Ollama on a single GPU; nothing is sent to a cloud API.

> Authorized use only. The agent operates exclusively against IPs in a
> configured scope, enforced in the runtime (not left to the model). The target
> is Metasploitable 2 running in a host-only VM lab.

## What it does

Given an in-scope target IP, the agent runs the full kill chain on its own:

```
scan_ports (nmap)
  -> lookup_cves (NVD) + searchsploit
    -> run_module (Metasploit, e.g. vsftpd_234_backdoor)
      -> root shell
        -> post-exploitation enumeration (uname, /etc/passwd, /etc/shadow, ...)
          -> findings + credentials recorded
            -> complete()
```

A validated run reaches a root shell on Metasploitable 2 in roughly two minutes,
then sweeps the host and persists the loot.

## Architecture

The core idea is **determinism in the runtime, the model only for judgment.**
The LLM decides which service to attack and which exploit fits; everything that
must be reliable is handled by code, not the model:

- **Scope enforcement** is in the runtime. The model cannot target an
  out-of-scope IP even if it tries.
- **Findings and credentials are runtime-generated** from real results (the
  module that opened a session, the actual command output, parsed `/etc/shadow`).
  The model is not allowed to author findings, which stops it from hallucinating
  loot the data does not support.
- **Exploit dedup** is enforced by a `UNIQUE(host_ip, port, module)` constraint
  plus a runtime guard, so the agent cannot loop on the same attempt.
- **SQLite is the durable memory.** Ports, attempted modules, sessions,
  findings, and credentials are persisted. A supervisor directive rebuilds the
  current state from SQL on every turn, so the model does not depend on chat
  history.
- **Context is pruned every iteration.** Because state lives in SQL and the
  directive re-injects it, old turns are dropped to keep the LLM context (and
  GPU memory) bounded instead of growing until inference stalls.
- **Reliability guards**: a per-request timeout so a stuck inference cannot wedge
  an engagement, and a one-engagement-at-a-time concurrency guard.

Every tool returns a structured `dict` with a `status` key. Tool errors return
error dicts; they never raise into the loop.

```
main.py / run.py        entry points (CLI run, or launcher + dashboard)
orchestrator.py         the agentic loop, supervisor directive, tool dispatch
config.py               scope, model, limits
prompts.py              system prompt
tools/recon.py          nmap
tools/intel.py          NVD API + SearchSploit
tools/exploit.py        Metasploit via pymetasploit3
tools/sessions.py       session management
tools/memory.py         SQLite operations
db/schema.sql           SQLite schema
event_bus.py            in-process pub/sub for telemetry
sse_routes.py           Server-Sent Events stream
dashboard_routes.py     engagement control + read API
web_app.py              Flask app
templates/ static/      dashboard UI
```

## Dashboard

A Flask + Server-Sent Events panel streams each engagement live: tool calls,
findings as they are discovered, the current module, and an event feed.
Engagements are persistent and scoped, so the history survives a reload. You can
click into a past run to replay its findings, feed, and modules, click a finding
to see its full evidence, start a new engagement, or end the current one.

SSE was chosen over WebSocket deliberately: the data flow is one directional
(server pushes telemetry, the browser only sends start and abort), so SSE is the
right shape and gives free auto-reconnect and a `curl`-able stream.

## Stack

- Ollama + Qwen2.5 14B (local, single GPU)
- Metasploit Framework + msfrpcd + pymetasploit3
- nmap
- SQLite (operational memory)
- NVD API + SearchSploit (CVE and exploit lookup)
- Flask + SSE (dashboard)
- Python 3, no agent frameworks, no Docker

## Setup

Requires a Python venv with the dependencies in `requirements.txt`, Ollama
running with the model pulled, the Metasploit Framework installed, and a target
VM reachable on a host-only network.

```bash
python -m venv venv
./venv/bin/pip install -r requirements.txt
cp .env.example .env   # set AUTHORIZED_SCOPE, NVD_API_KEY, etc. (.env is gitignored)
```

## Running

The launcher preflights the dependencies, starts msfrpcd if it is down, and
serves the dashboard:

```bash
python run.py            # preflight + start msfrpcd + serve dashboard on :5000
python run.py --check    # read-only dependency report, then exit
```

Or run a single engagement from the CLI:

```bash
python main.py 192.168.56.101
```

Open the dashboard at http://127.0.0.1:5000, enter an in-scope target, and start
an engagement.

## Tests

```bash
pytest -q
```

Tests cover the loop, SQLite memory and its enforcement, CVE intel, and the
Phase 4 hardening (engagement persistence, context pruning, runtime-only
findings, enumeration and shadow parsing). No live target, Ollama, or Metasploit
is required to run them.

## Status and roadmap

Built in phases. The core loop, SQLite memory, CVE and exploit lookup, and a
monitoring dashboard are working; live runs against Metasploitable 2 reach root
and document the result.

Current focus is making the agent a full-suite pentester: instead of stopping at
the first root shell, it should exploit and document every service, the way a
real engagement does. The prerequisite, memory and context management that holds
up across a long multi-service run, is largely in place. Planned next:

- Per-service coverage and runtime-driven completion (do not stop at first root)
- Password hash cracking (dumped hashes are stored but not yet cracked)
- A model-generated After Action Report per engagement
- A knowledge base (embeddings + exploitation playbooks) for domain expertise
