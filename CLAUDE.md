# MSF-Agent

Autonomous penetration testing agent. Local LLM drives the agentic loop.

## Stack
- Ollama + Qwen2.5 14B (localhost:11434, RTX 3080)
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
Test count is intentionally not recorded here; run `pytest -q` for the current
number. Reconcile this checklist only at phase boundaries.
- [x] db/schema.sql
- [x] config.py
- [x] prompts.py
- [x] tools/memory.py
- [x] orchestrator.py
- [x] main.py
- [x] tools/recon.py
- [x] tools/intel.py (Phase 3)
- [x] tools/exploit.py (Phase 3)
- [x] tools/sessions.py (Phase 3)
- [x] tests/test_memory.py
- [x] tests/test_loop.py
- [x] tests/test_memory_enforcement.py
- [x] tests/test_intel.py
- [x] tests/test_phase4.py
- [x] web dashboard (built ahead of phase, see Phase 4 progress note below):
      event_bus.py, sse_routes.py, dashboard_routes.py, web_app.py,
      templates/index.html, static/dashboard.{js,css}

## Current phase
Phase 1: Complete. Phase 2: Complete. Phase 3: Complete. Phase 4 is current
(hardening and tuning).

## Phase 4 progress (resume here)
Still NONE of this is committed. Untracked: web files + run.py. Modified/unstaged:
orchestrator.py, dashboard_routes.py, .gitignore, requirements.txt, CLAUDE.md.
Leave staging/commit to the user. 93 tests pass.

### Session of 2026-06-12 (most recent, resume from NEXT below)
- run.py: single launcher. Preflights Ollama/msfrpcd/target, auto-starts msfrpcd
  in foreground (-f, so it is tracked and torn down on exit; without -f msfrpcd
  daemonizes and orphans), then serves the dashboard. Flags: --check (read-only
  report), --no-msfrpcd. Does NOT start Ollama or the VM by design.
- Phase 6 transport decision locked to Flask + SSE (not FastAPI + WebSocket); see
  the Phase 6 section for the rationale.
- Concurrency guard: only ONE engagement at a time. orchestrator has
  claim_engagement/active_engagement/release_engagement (single global slot,
  because _clear_sessions() wipes ALL msf sessions regardless of target).
  /engagement/start returns 409 if busy; a _run_engagement wrapper releases the
  slot in finally. Closes the double-click-spawns-two-runs footgun.
- Findings now actually land in the dashboard (was the visible bug: empty table):
  * AAR gap #1 DONE: complete(findings=...) is persisted, not just emitted, via
    _normalize_finding (maps host->host_ip, defaults title/severity, and CRITICAL
    FIX: serializes non-string evidence -- the model sends evidence as a list of
    {command,output} dicts, which silently failed to bind to the TEXT column).
  * Auto-finding on shell open: when run_module opens a session, a finding is
    written + emitted in the runtime (severity critical if root), independent of
    the model. This is why findings now appear even if the model never calls
    memory_write('finding').
  * Open ports -> info findings: each scan_ports open port is written once per run
    as severity "info" (the app's informational tier; no sev-informational CSS).
  * _record_finding() centralizes write+emit and LOGS a "finding write failed:"
    event on DB rejection, so silent loss can't recur.
- Verified live: full kill chain to root again; auto-finding persisted to SQLite
  AND /api/bootstrap. complete() finding previously vanished (the evidence-list
  bug) -- now fixed and unit-verified against the exact failing payload.

### Auto-enumeration on root shell (DONE 2026-06-12, not yet live-run verified)
When a root shell opens, the runtime sweeps the host (not delegated to the model).
In orchestrator.py: _enumerate_root() fires from the auto-root block when
username == "root". Runs _ROOT_ENUM_STEPS (uname -a, /etc/issue, hostname,
/etc/passwd, ip addr|ifconfig -a, netstat -tlnp|ss -tlnp, ps aux, sudo -n -l),
each output stored as an info finding via _record_finding. _run_enum_cmd handles
the primary/fallback pairs. /etc/shadow is captured as a high finding AND parsed
by _persist_shadow_credentials into the credential table (skips * / ! / !!-prefix
/ empty hashes) -- this CLOSES AAR gap #2 (credential table was always empty).
User chose "all of it" for scope. Tested: test_root_shell_triggers_enumeration_
and_parses_shadow added; the whoami-fallback test's mock was switched to a
command-aware function (a fixed side_effect list was exhausted by the new enum
calls). 94 tests pass. NEXT: live-run verify enumeration + credentials end to end.

### Stuck-inference + context management (DONE 2026-06-12)
A live run wedged: the orchestrator hung inside one client.chat() call (model at
66% CPU, zero events for 70s+, DB frozen). Root cause: unbounded growth of the
in-context `messages` list slowed inference into a crawl, and there was no
timeout on the model call, plus abort is only checked between iterations so it
could not interrupt a stuck call. Fixes:
- config.OLLAMA_TIMEOUT (default 120s) passed to ollama.Client(timeout=...); a
  stuck/runaway generation now raises and ends the engagement cleanly (emits a
  log) instead of hanging forever. Tradeoff: one timeout ends the run; with
  pruning, slow inference should be rare. Finer-grained mid-call abort is future.
- _prune_messages(messages, cap) keeps the system prompt + last
  (CONTEXT_MAX_MESSAGES-1) messages (default 16), dropping orphaned tool results
  at the window start. Called at the top of each iteration. Safe because the
  supervisor directive re-injects port/session/tried-module state from SQLite
  every turn, so old history is redundant. Keeps KV cache / VRAM bounded.
- Runtime now auto-writes scanned ports to the port table (memory.write("port",
  [...with host_ip...])) right after scan_ports, so the directive's untried-
  services rule always has data even though context pruning means we cannot rely
  on the model having called memory_write('port').
- Tests: TestContextPruning added (3 cases). 97 tests pass.
Note AAR gap #4 (block-buffered orchestrator stdout) is separate and still open;
watch the SSE /events stream for live state, not server stdout.

### Engagement lifecycle + history (DONE 2026-06-12, automated-verified; live browser run pending)
Dashboard is now engagement-scoped and persistent instead of live-only. See
[[project-engagement-lifecycle-aar]] memory for the direction and the FUTURE AAR
goal (do not build the AAR until directed; the `engagement.aar` column and the
POST /engagement/<id>/end endpoint are the reserved hooks).
- Schema (db/schema.sql): new `engagement(id,target,status,started_at,ended_at,
  summary,aar)` and `event(id,engagement_id,type,payload,ts)` tables + indexes.
  `finding` gained `engagement_id`. tools/memory.py `_migrate()` runs before the
  executescript and ALTERs `finding` to add the column on pre-existing DBs (must
  precede the new finding index). New helpers: create_engagement, finish_
  engagement, write_event; finding INSERT now includes engagement_id.
- orchestrator.py: run() creates the engagement row up front; the emit closure
  persists every event via write_event; findings are stamped with engagement_id
  (threaded through _record_finding / _enumerate_root); finish() writes terminal
  status+ended_at+summary; _clear_engagement_tables NO LONGER deletes findings
  (they are engagement-scoped and must persist for history).
- dashboard_routes.py: GET /engagements (list+active), GET /engagement/<id>
  (engagement + findings + parsed events), POST /engagement/<id>/end (aborts if
  running; FUTURE AAR hook). /api/bootstrap now returns {engagements, active}
  instead of a global findings dump.
- Frontend: End Engagement button; the Engagements panel is the clickable
  history; clicking a run loads /engagement/<id> and replays findings + feed +
  modules read-only; live vs archived view modes (view banner + back-to-live);
  bootstrap restores the active run. dashboard.js largely rewritten.
- Tests: TestEngagementPersistence added (engagement row lifecycle via a real
  mocked run; findings carry engagement_id; events persisted; findings survive
  the clear). 99 tests pass. Pre-existing findings in agent.db have NULL
  engagement_id (orphaned, harmless).
- NEXT: live browser run to confirm history/end/click-to-replay end to end.

### Session of 2026-06-11
What works now:
- Full kill chain validated live against Metasploitable 2 (192.168.56.101):
  scan -> lookup_cves (CVE-2011-2523) -> searchsploit -> run_module
  (exploit/unix/ftp/vsftpd_234_backdoor) -> ROOT shell -> post-exploit ->
  complete(). ~6 iterations, ~2 minutes to root.
- Flask monitoring dashboard with live SSE streaming (built ahead of its
  Phase 6 slot, intentionally, for observability during Phase 4 tuning).
  Stack is Flask + Jinja + SSE (diverges from the planned FastAPI + WebSocket).
- orchestrator.run() now takes an optional engagement_id and emits
  engagement_started / module_started / module_finished / finding / log /
  engagement_finished on the in-process EventBus. Added request_abort() +
  cooperative cancel check at the top of each loop iteration.
- dashboard_routes /engagement/start launches orchestrator.run on a daemon
  thread IN-PROCESS (required so SSE sees the events); /abort sets the cancel
  flag. /api/bootstrap reads findings from SQLite for first paint.
- 93 tests pass; run(target) stays backward-compatible (engagement_id defaults).

Known gaps from the live-run AAR (backlog):
1. DONE (2026-06-12). complete(findings=...) now persisted via _record_finding +
   _normalize_finding; auto-finding on shell open added too.
2. DONE (2026-06-12). /etc/shadow parsed into the credential table by
   _persist_shadow_credentials as part of the root-shell auto-enumeration.
3. No dedup guard on lookup_cves (model called the same lookup twice). NOT done.
4. In-process orchestrator stdout is block-buffered, so the server-side trace
   is lost; events still stream fine. Line-buffer or log to a file. NOT done.
   (Workaround in use: watch the SSE /events stream, which is unaffected.)
5. DONE (2026-06-12). Findings are runtime-generated ONLY -- the model can no
   longer author findings (complete(findings) dropped; memory_write('finding')
   blocked by _model_memory_write; "write findings" removed from directives).
   This stopped a hallucinated finding ("Root Shell Gained via msfadmin Account"
   claiming a hash was cracked when nothing was cracked -- all credential.password
   are NULL, root came from the vsftpd backdoor).
6. DONE (2026-06-12). Dashboard timestamps were wrong (sqlite stores UTC; JS read
   it as local, off by the tz offset, even showing the next day). fmtTime now
   tags sqlite datetime strings as UTC before converting to local.

Bigger backlog (user direction, NOT started):
A. HASH CRACKING. Dump /etc/shadow hashes are stored but never cracked
   (credential.password is always NULL). Add a john/hashcat step that writes the
   recovered plaintext into credential.password so "got password from hash" is a
   real, provenance-backed fact. Lower priority than B per the user.
B. FULL-SUITE PENTESTER (the big one, user priority). The agent must NOT stop at
   the first root shell. Like a real pentester it should exploit and DOCUMENT
   every vulnerability/service, not just the first that pops a shell. HARD
   PREREQUISITE the user called out: memory/context management must be solid
   first, or chasing many services fills the context window fast. Today Rule 1
   ("STOP EXPLOITING" on first root) is the opposite of this goal -- it ends the
   engagement at first root. Needs: per-service/per-vuln tracking that survives
   pruning (SQLite already holds ports/tried_module/findings; the supervisor
   directive already drives "untried services"), a notion of "engagement done"
   = all services attempted+documented (not first-root), and context discipline
   so a long multi-vuln run does not blow up. See the dedicated review/plan.
Full AAR: ~/.claude/plans/give-me-an-after-golden-crane.md

How to restart the runtime (daemons die between sessions):
- quick start: python run.py    preflights Ollama/msfrpcd/target, starts msfrpcd
                                 if down (foreground, -f, torn down on exit),
                                 then serves the panel. python run.py --check for
                                 a read-only dependency report.
- msfrpcd:  msfrpcd -P msf -U msf -S -a 127.0.0.1   (port 55553, NO SSL)
- panel:    python web_app.py                        (http://127.0.0.1:5000)
- engagement (CLI): python main.py 192.168.56.101
- needs: Ollama up (11434), Metasploitable2 VM powered on and reachable.
  run.py does NOT start Ollama (system service) or the VM (VirtualBox).

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

Direction decision (2026-06-12): keep the RAG playbook pipeline as planned
(embedding retrieval feeds playbook context to the main 14B model). Considered
and declined a pivot to deterministic "skills"/parameterized-playbook tools plus
a separate small router model. Reasons: a second generative model contends for
VRAM on the single RTX 3080 for little gain, and most routing is better handled
by deterministic code we already have (supervisor directive, scan stuck-
detection, untried-services logic). The deterministic-routine approach is still
used selectively for fixed procedures where per-step reasoning adds nothing (see
_enumerate_root, the root-shell enumeration sweep); embedding-based skill
*selection* is exactly what this RAG phase already provides. Revisit a router
model only if a decision genuinely needs language understanding rules cannot
capture.

### Phase 6: Web interface (blocked on Phase 5)
Goal: real-time browser UI for demo and portfolio

Transport decision (2026-06-12): Flask + Server-Sent Events, NOT the originally
planned FastAPI + WebSocket. Rationale: the data flow is one-directional (server
pushes tool calls, findings, iteration/elapsed, log lines; the browser only sends
start/abort, which are plain HTTP POSTs). SSE is the right shape for that. It also
gives free EventSource auto-reconnect (resumes from Last-Event-ID) and a stream
you can curl during tuning, with no upgrade handshake or hand-rolled keepalive.
WebSocket would leave half the duplex channel unused for a single-user localhost
tool. Revisit WebSocket only if an interactive in-browser session shell is added
(genuinely bidirectional); it can run alongside SSE without discarding this work.

Most of this phase already exists, built ahead of slot during Phase 4 for
observability (event_bus.py, sse_routes.py, dashboard_routes.py, web_app.py,
templates/index.html, static/dashboard.{js,css}). Remaining Phase 6 scope is
polish against the feature list below, not a rebuild.
- Flask backend with SSE support (bus -> /events stream)
- Orchestrator runs in a background daemon thread, in-process so it emits to the
  same EventBus the SSE stream reads from; streams events to the browser
- Browser receives live feed of: tool calls, tool results, iteration count,
  elapsed time, findings as they are discovered
- Single page UI showing:
    - Target IP input and Start/Stop controls (wired and verified 2026-06-12)
    - Live event log (tool name, arguments, result, timestamp)
    - Findings table (host, port, title, severity, evidence)
    - Memory panel (what the agent currently knows about the target)
    - Iteration counter and elapsed time
- Clean, minimal design, dark theme, no external CSS frameworks
- Flask serves the HTML on GET /, SSE on GET /events
- Agent output goes to the EventBus (and the SSE stream), not just stdout
- Stop button triggers cooperative cancel via request_abort(), not a hard kill
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