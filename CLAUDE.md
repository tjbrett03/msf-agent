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
- [ ] db/schema.sql
- [ ] config.py
- [ ] prompts.py
- [ ] tools/memory.py
- [ ] tests/test_memory.py
- [ ] orchestrator.py
- [ ] main.py
- [ ] tools/recon.py
- [ ] tools/intel.py
- [ ] tools/exploit.py
- [ ] tools/sessions.py

## Current phase
Phase 1: Core agentic loop. No live target required yet.

## Phases

### Phase 0: Environment (complete)
- Ubuntu 24.04 installed
- VirtualBox installed
- Ollama + Llama 3.1 8B confirmed on GPU
- Metasploit Framework installed
- Python venv set up at ~/msf-agent/venv
- Dependencies installed: pymetasploit3, ollama, requests
- Tool calling confirmed working

### Phase 1: Core agentic loop (current)
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

### Phase 2: SQLite memory (blocked on Phase 1)
Goal: prove the agent reads and writes memory reliably
- Runtime enforcement of tried_module check
- Memory read-before-act pattern verified in practice
- tests/test_memory_enforcement.py
- Prompt engineering iteration for memory discipline

### Phase 3: CVE and exploit lookup (blocked on Phase 2)
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

### Phase 4: Hardening and tuning (blocked on Phase 3)
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

### Phase 6: Documentation and packaging (blocked on Phase 5)
Goal: portfolio-ready project
- README with architecture explanation
- Architecture diagram
- Demo recording
- GitHub cleanup
- Kali packaging (optional, stretch goal)

## Do not work ahead of current phase
If asked to build something from a future phase, decline and flag it.