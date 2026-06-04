# MSF-Agent

Autonomous penetration testing agent. Local LLM drives the agentic loop.

## Stack
- Ollama + Llama 3.1 8B (localhost:11434, RTX 3080)
- Metasploit Framework + msfrpcd + pymetasploit3
- nmap (subprocess)
- SQLite (operational memory, ~/msf-agent/db/agent.db)
- NVD API + SearchSploit (CVE/exploit lookup)
- Metasploitable 2 in VirtualBox (target, host-only network)

## Hard rules
- No LangChain or agent frameworks, loop is hand-rolled
- No Docker
- No web search
- No ChromaDB yet, comes after core loop is proven
- No packages installed outside venv without asking
- Every tool function returns a dict with a "status" key
- Tool errors return structured dicts, never raise exceptions to orchestrator
- Scope enforcement happens in runtime, never delegated to model
- Comments explain why not what, no em dashes

## Project structure
main.py           entry point
orchestrator.py   agentic loop
config.py         scope, model, limits
prompts.py        system prompt
tools/recon.py    nmap
tools/exploit.py  pymetasploit3
tools/sessions.py session management
tools/memory.py   SQLite operations
tools/intel.py    NVD + SearchSploit
db/schema.sql     SQLite schema
db/agent.db       SQLite database (gitignored)

## Build status
- [x] db/schema.sql
- [x] config.py
- [x] prompts.py
- [x] tools/memory.py
- [x] tests/test_memory.py (17 tests)
- [x] orchestrator.py
- [x] main.py
- [x] tools/recon.py
- [x] tests/test_loop.py (7 tests)
- [x] tests/test_memory_enforcement.py (5 tests)
- [ ] tools/intel.py (Phase 3)
- [ ] tools/exploit.py (Phase 3)
- [ ] tools/sessions.py (Phase 3)

## Current phase
Phase 1: Complete. Phase 2: Complete. Phase 3: Complete. Phase 4 is next (prompt engineering).

## Phase 1 completion notes
- All 24 tests passing (17 memory, 7 loop)
- e2e test against real Ollama confirmed: tool dispatch works, tool names resolve,
  memory tools execute, nmap fires real scans
- Bug fixed: Ollama Python library requires {"type": "function", "function": {...}}
  wrapper on tool schemas -- flat schemas cause tool name to be empty string
- Known prompt engineering issue: model doesn't reliably call complete() when stuck,
  tends to alternate text response / tool call and burn iterations. To be addressed
  in Phase 2 prompt tuning.
- e2e test lives at tests/e2e_real_model.py (uses temp DB, 10 iter / 120s limits)

## Phase 3 completion notes
- 42 tests passing (added 13 intel tests)
- tools/intel.py: lookup_cves (NVD API) and searchsploit (CLI) both wired in
- tools/exploit.py: real pymetasploit3 connection, payload auto-selection from
  preference list (cmd/unix/bind_netcat first), polls 20s for session
- tools/sessions.py: list_sessions, run_command (sentinel echo pattern),
  close_session
- All tools wired into orchestrator TOOL_SCHEMAS and TOOL_MAP
- config.py: MSF_SSL default changed true->false (msfrpcd -S disables SSL),
  NVD_API_KEY added, AUTHORIZED_SCOPE made dynamic via env var
- python-dotenv support added, .env created (gitignored)
- Live runs conducted against Metasploitable 2 (192.168.56.101)
- Bugs found and fixed during live runs:
  - model forgot target IP -> anchored TARGET in system prompt (repeated 3x)
  - scope error gave no hint -> error now includes authorized scope list
  - memory_write passed strings/lists -> tool description now has per-category
    dict examples
  - run_module options passed as string -> coerce non-dict options to {}
  - run_module port passed as string -> coerce to int
  - kickoff message "call complete() when done" triggered immediate exit ->
    replaced with explicit "start by calling scan_ports" instruction
- Remaining model behavior issues deferred to Phase 4:
  - model re-scans repeatedly when stuck instead of calling complete()
  - memory_write still passes Python dict literal as string (not valid JSON)
  - model does not progress through all services after one exploit fails

## Phase 2 completion notes
- All 29 tests passing (17 memory, 7 loop, 5 enforcement)
- Runtime tried_module guard in _dispatch blocks duplicate run_module calls at the
  orchestrator level, independent of model behavior
- Orchestrator auto-writes tried_module after each run_module so the guard holds
  even if the model forgets to call memory_write
- run_module added as stub (real Metasploit connection wired in Phase 3)
- System prompt stripped of non-existent tool references, memory discipline rules
  tightened and reordered to match actual workflow
- host write fixed: ON CONFLICT DO NOTHING changed to update hostname/os_guess

## Phases

### Phase 0: Environment (complete)
- Ubuntu 24.04 installed
- VirtualBox installed
- Ollama + Llama 3.1 8B confirmed on GPU
- Metasploit Framework installed
- Python venv set up at ~/msf-agent/venv
- Dependencies installed: pymetasploit3, ollama, requests
- Tool calling confirmed working

### Phase 1: Core agentic loop (complete)
Goal: prove the loop works before adding complexity
- db/schema.sql
- config.py
- prompts.py
- tools/memory.py
- tests/test_memory.py
- orchestrator.py with mocked scan_ports stub
- main.py
- tools/recon.py (nmap subprocess, real implementation)
- tests/test_loop.py (loop test with mocked tools)
Do not add Metasploit, CVE lookup, or real targets in this phase.

### Phase 2: SQLite memory (complete)
Goal: prove the agent reads and writes memory reliably
- Runtime enforcement of tried_module check
- Memory read-before-act pattern verified in practice
- tests/test_memory_enforcement.py
- Prompt engineering iteration for memory discipline

### Phase 3: CVE and exploit lookup (complete)
Goal: agent can reason about vulnerabilities before acting
- tools/intel.py (NVD API + SearchSploit)
- tests/test_intel.py
- Wire intel tools into orchestrator
- Import Metasploitable 2 into VirtualBox
- Configure host-only network
- Start msfrpcd
- tools/exploit.py (real implementation)
- tools/sessions.py
- First live run against Metasploitable

### Phase 4: Hardening and tuning (current)
Goal: reliable autonomous operation
- Prompt engineering for consistent behavior
- Stuck detection
- Context window pruning
- Handle edge cases and failure modes
- Extended test runs against Metasploitable

### Phase 5: ChromaDB knowledge base (blocked on Phase 4)
Goal: agent has domain expertise beyond CVE data
- nomic-embed-text via Ollama
- ChromaDB setup and ingestion pipeline
- Exploitation playbooks authored and ingested
- knowledge_search() tool wired in

### Phase 6: Web interface (blocked on Phase 5)
Goal: real-time browser UI for demo and portfolio
- FastAPI backend with WebSocket support
- Orchestrator runs in background thread, streams events to WebSocket
- Browser receives live feed of: tool calls, tool results, iteration count,
  elapsed time, findings as they are discovered
- Single page UI showing:
    - Target IP input and Start/Stop controls
    - Live event log (tool name, arguments, result, timestamp)
    - Findings table (host, port, title, severity, evidence)
    - Memory panel (what the agent currently knows about the target)
    - Iteration counter and elapsed time
- Clean, minimal design, dark theme, no external CSS frameworks
- FastAPI serves the HTML on GET /, WebSocket on /ws
- Agent output goes to WebSocket, not just stdout
- Stop button triggers clean shutdown, not a hard kill
- All existing tool and orchestrator logic stays untouched

### Phase 7: Documentation and packaging (blocked on Phase 6)
Goal: portfolio-ready project
- README with architecture explanation
- Architecture diagram
- Demo recording
- GitHub cleanup
- Kali packaging (optional, stretch goal)

## Do not work ahead of current phase
If asked to build something from a future phase, decline and flag it.