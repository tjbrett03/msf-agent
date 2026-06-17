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
tools/cracking.py John the Ripper handoff (crack_hashes), agentic-rebuild branch
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
Phase 1-3: Complete. Phase 4 (hardening/tuning) is where the AGENTIC REBUILD
happened. Active work now lives on branch `agentic-rebuild` (see below); the
older Phase 4 / Phase A+B notes further down are HISTORY of the pre-rebuild
architecture and describe behavior the rebuild deliberately replaced.

## Agentic rebuild (branch: agentic-rebuild) -- RESUME HERE
The handoff at ~/Downloads/enumeration_handoff(1).md redefined the project: turn
the hardcoded exploitation script with an LLM stapled on into a real autonomous
agent. North star: THE RUNTIME DELIVERS STATE AND RECORDS TRUTH; THE MODEL
DECIDES EVERY ACTION. A decision (which service, which module, escalate vs pivot,
what to enumerate, when done) belongs to the model. A fact (shell opened, uid=0,
this hash, this port open, this module fired) belongs to the runtime.

BRANCHING (per the handoff's method, user-approved):
- `v1-hardcoded` tag = the known-good reliable baseline (the old stop-at-root,
  hardcoded-sweep version). It is the fallback demo and does NOT get deleted.
- `agentic-rebuild` branch = all rebuild work. Cut from the baseline after the
  pre-rebuild bug fixes were committed.
- DO NOT merge agentic-rebuild to master until it demonstrates JUDGMENT on a
  SECOND, UNSEEDED VM (a target it was not tuned for). Metasploitable 2 is only
  the wiring check. The rule of thumb: if you catch yourself moving a DECISION
  back into the runtime to make the Metasploitable run look cleaner, stop -- that
  is the project failing, not the model. Fix it with prompt doctrine or tool
  wording, or accept the variance. Hardcoding a decision is only correct on the
  baseline.

WHAT SHIPPED (steps 0-8, each a committed checkpoint on agentic-rebuild; run
`git log v1-hardcoded..HEAD` for the per-step commits):
1. Trust split + schema. finding gained source ('runtime'|'model') + confirmed
   (0/1); new service_assessment table (host_ip, port, vulnerable, severity,
   cve_ids). _model_memory_write now BLOCKS model credential writes (ok+note) and
   ALLOWS model findings stamped source=model/confirmed=0; _record_finding stamps
   runtime/confirmed=1. credential is runtime-only (so it needs no confirmed
   column; every row is ground truth by construction).
2. Loot floor. _capture_loot(output, target, emit, eid) runs on every successful
   run_command AND enumerate result: shadow-hash lines -> credential table via
   _persist_shadow_credentials (only lines matching ^[^:]+:$id$...: , never raw
   output); private keys / AWS keys / inline creds -> runtime findings (reviewable
   feed, not the credential table). Makes it safe to hand enumeration to the model.
3. Documentation axis. After a scan, the runtime auto-assesses EVERY open port via
   lookup_cves (through _dispatch so it shares the per-run CVE cache) and writes a
   service_assessment row (vulnerable/severity/cve_ids). Documentation is
   exhaustive and runtime-owned, complete before the model could ever finish.
   service_assessment is cleared per run in _clear_engagement_tables.
4. Removed the hardcoded root sweep (_enumerate_root, _ROOT_ENUM_STEPS,
   _run_enum_cmd and the auto-call). Kept _persist_shadow_credentials and all
   runtime shell/root detection (warm_up, id, uid=0, breach finding). Added a
   DEMOTED enumerate(session_id, category) tool (sessions.enumerate_session) as a
   convenience FALLBACK battery (system/users/network/processes/privileges/all),
   not the primary path. Does not read /etc/shadow.
5. Directives = state injection (the core change). build_supervisor_directive
   rewritten from imperatives to facts: root-shell / user-shell state lines carry
   loot counts + untried services; Rule 3's completion gate ("do not call
   complete() until each port attempted") DELETED; scan-twice kept as a fact.
   _sudo_l_status kept; it now feeds a state line. Helpers _untried_services
   (severity-annotated) and _loot_counts re-inject durable state every turn.
6. Model-ranked selective exploitation. prompts.py rewritten from rigid
   WORKFLOW/IF-ROOT control flow to attacker doctrine: document all (automatic),
   exploit selectively (rank candidates, pick the single best path to root), seek
   root, escalate before pivoting, loot what you take, completion is the model's
   call. memory_read schema now lists service_state/service_assessment so the
   doctrine's "read the assessment" is actionable.
7. Completion floor. Model decides complete(); the runtime refuses EXACTLY ONE
   case via _completion_blocked(target): a shell is open AND zero loot captured
   (no credential row and no "Loot --" finding). No documentation gate, no
   attempt-every-port gate. A completion with documented-but-unexploited vulns and
   no shell is valid.
8. Hash cracking. tools/cracking.py crack_hashes(host_ip) feeds uncracked hashes
   (hash present, password empty) to `john` via subprocess, then `john --show`,
   and writes back ONLY real cracked plaintext via memory.set_credential_password
   (keyed on host_ip+hash). Defensive like searchsploit (john-missing/timeout ->
   structured error, never raises). No new pip packages; shells out to system john.

LIVE WIRING-CHECK RESULT (2026-06-17, engagement 1df4811f vs Metasploitable 2):
Full autonomous run, completed on the model's own call at iter 16. Worked: scan
-> auto-assess all ports (21 CRITICAL, 513 HIGH, 80 MEDIUM, ...) -> model RANKED
and chose vsftpd itself -> root shell -> model-driven enumeration (plus the
enumerate fallback) -> loot floor captured shadow creds + secrets -> model
decided completion -> floor allowed it. This is the architecture working, not a
script. The directive feed read as state ("State: root shell ... Loot captured
so far: N credentials, M findings. Decide what to pull."), exactly as designed.

WHAT TO DO NEXT (in rough priority):
A. FIX (real fact-recording bug): DUPLICATE CREDENTIALS. The model re-cat'd
   /etc/shadow and the loot floor's _persist_shadow_credentials does a plain
   INSERT with no uniqueness, so 7 real creds were recorded as 14. The runtime is
   supposed to record TRUTH. Fix: add UNIQUE(host_ip, username, hash) on
   credential (or upsert / dedup-on-write). This is the first thing to fix; it is
   a runtime correctness defect, not model judgment.
B. TIGHTEN loot noise (runtime, low risk): the _PASSWORD_ASSIGN_RE
   (password\s*[=:]\s*\S+) fired ~18 times on config-file comments (php.ini etc.)
   during `grep -r password`, flooding the findings feed. Tighten the pattern or
   drop the bare password= heuristic; keep private-key/AWS/connection-string.
C. PROMPT-DOCTRINE TUNING (NOT rails -- fix in prompts.py only): the model (a)
   looped on enumerate(all) for ~8 iterations re-reading shadow instead of
   progressing, (b) never called crack_hashes despite holding 7 hashes, and (c)
   stopped after a single service with 513/HIGH and 80/MEDIUM still untried.
   (a)/(b) are efficiency/closure gaps; (c) is defensible under "exploit
   selectively / completion is your call" but shows the model defaulting to
   minimal effort. Per the handoff: resist hardcoding any of these back into the
   runtime. Nudge with doctrine wording (e.g. "after looting hashes, crack them";
   "do not re-run the same sweep").
D. THE REAL TEST (unproven): stand up a SECOND, UNSEEDED vulnerable VM and judge
   the agent there. Metasploitable was only the wiring check. Do not merge to
   master until judgment is demonstrated on the unseeded box.
E. DEFERRED (do not build yet, per handoff): step 9 report/AAR stage (reads only
   confirmed items; the engagement.aar column is the reserved hook), and the
   RAG/vector memory boundary (search_knowledge + episodic RAG over confirmed
   loot). SQLite owns "this, exactly"; Chroma, eventually, owns "like this".

How to run the live test: VirtualBox VM powered on, then `python run.py`
(preflights Ollama/msfrpcd/target, auto-starts msfrpcd in foreground, serves the
dashboard at http://127.0.0.1:5000). Watch the SSE/event feed (or
GET /engagement/<id>), NOT server stdout (still block-buffered, AAR gap #4).

## Phase 4 progress (HISTORY -- pre-rebuild architecture, on master/baseline)
NOTE: everything below predates the agentic rebuild above and describes the OLD
behavior the rebuild replaced (stop-at-root Rule 1, hardcoded _enumerate_root
sweep, model forbidden from authoring findings). Kept as project history; for
current state read the "Agentic rebuild" section above.
STATUS (end of 2026-06-14 session): PR #1 (engagement-suite) MERGED into master
(96bd8f0). Two loose-end fixes on master (c57c872). Phase A + session reliability
DONE, LIVE-VERIFIED, committed on branch `feature/full-suite-pentester` (commit
9c92986, one ahead of master, NOT pushed). 117 tests pass.

RESUME HERE NEXT SESSION:
- Branch `feature/full-suite-pentester` is checked out; working tree clean.
- NEXT TASK = implement Phase B (full-suite pentester). The foundation plan is
  written and APPROVED by the user: ~/.claude/plans/lay-down-the-foundation-
  curried-moore.md (read it first -- it has the exact files/functions to change).
- "Done" definition the user chose (module-level): record each module outcome
  (tried_module already does), loop again, skip what is tried (guard already does),
  and keep going until no service is 'untried' AND the model has no new module to
  propose. Close a root session after it auto-documents so the loop continues.
- Open thread: user said "use remote control" (RemoteTrigger / claude.ai routine)
  right before stopping -- likely wanted to drive/schedule the Phase B run
  remotely. Clarify intent before setting up any routine (it is outward-facing).
- Daemons (msfrpcd, dashboard) were torn down at end of session; restart per the
  "How to restart the runtime" section below. The agent.db has prior engagements
  including the verified clean run 840f8236 (root + 7 creds + complete).

IMMEDIATE LOOSE ENDS: BOTH DONE (2026-06-14, commit c57c872).
1. DONE. prompts.py no longer tells the model to author findings/credentials
   (runtime records them; model writes were dropped). Stop-at-root flow kept.
2. DONE. run.py installs a SIGTERM handler that sys.exit(0) so atexit tears down
   msfrpcd on `kill`/programmatic restart, not just Ctrl+C.

### Phase A: memory/context hardening (DONE + LIVE-VERIFIED 2026-06-14)
Prereq for Phase B: durable per-service progress that survives context pruning,
plus stop wasting context on duplicate CVE lookups.
- Schema: new `service_state(host_ip, port, service, status, outcome, reason,
  engagement_id, updated_at)`, UNIQUE(host_ip, port). status ladder:
  untried -> attempted -> exploited / documented / skipped. Cleared per run in
  _clear_engagement_tables alongside port/tried_module (live run state, not
  history). New table so CREATE IF NOT EXISTS covers fresh + existing DBs; no
  _migrate ALTER needed.
- tools/memory.py: service_state wired into read/query/write (UPSERT on
  host_ip+port). seed_service_state() is INSERT-OR-IGNORE (a re-scan must never
  regress an exploited port to untried). advance_service_state() is FORWARD-ONLY
  via _STATUS_RANK (a 2nd module's 'attempted' cannot knock a port off
  'exploited'); outcome/reason refresh ONLY when the event advances/ties the
  status, so a rank-ignored backward event (duplicate module that errors on an
  already-documented port) cannot clobber the good outcome.
- orchestrator.py runtime populates it (NOT the model): seed untried per open
  port on scan; advance 'attempted' after each run_module; 'exploited' when a
  session opens; 'documented' after the breach finding + root enum are recorded.
  Supervisor directive Rule 3 now reads service_state for untried ports (was
  derived from port - tried_module). Rule 1 (STOP at root) intentionally
  unchanged -- that flip is Phase B.
- lookup_cves dedup (AAR gap #3 DONE): per-run _cve_cache in _dispatch keyed by
  (service, version), reset at run start (safe: single-engagement concurrency
  guard). Repeat lookup returns cached result + note; only ok results cached so a
  transient NVD error still retries.

### Session reliability (DONE 2026-06-14, surfaced by Phase A live verification)
The first two Phase A live runs wedged/degraded in post-exploitation. Root cause:
a freshly opened backdoor shell is not ready for ~1-2s, so the first id/whoami
writes were dropped; pymetasploit3's run_with_output `timeout` does not bound the
write/RPC, so the call hung forever (run 1) or, with a naive thread timeout,
abandoned readers piled onto the same ShellSession and stole each other's bytes,
cascading 40s timeouts (run 2). Fixes in tools/sessions.py + orchestrator.py:
- warm_up(session_id): after a shell opens, drain the banner then write a unique
  split-token echo and wait for its OUTPUT to round-trip before issuing real
  commands. _split_token_echo keeps the literal token out of the typed line so a
  command-echoing shell cannot false-match. THIS is the core fix (root now
  confirmed reliably).
- _session_lock serializes all shell I/O so there is never a second concurrent
  reader; a wedged call keeps the lock (parks the session) rather than letting a
  new reader corrupt the stream. Hard wall-clock bound (_bounded_locked, join =
  timeout + _HANG_GRACE) is the ceiling.
- Orchestrator: warm up before the id probe; if the shell never becomes
  responsive, CLOSE it and write NO session row (an unusable shell must not drive
  the Rule 2 privesc loop -- that loop burned all 50 iterations in run 2).
- Tests: TestSessionReliability (warm-up round-trip, busy-lock, hard timeout,
  split-token). TestSessionAutoWrite tests now mock sessions.warm_up=ready.
- LIVE VERIFIED 2026-06-14 (engagement 840f8236): scan -> vsftpd backdoor -> warm
  up -> root confirmed -> /etc/shadow parsed into 7 credentials -> port 21
  documented -> clean complete(), 7 iterations, ~77s. The two prior wedge/loop
  failure modes are both gone. 117 tests pass.

PHASE A IS DONE AND LIVE-VERIFIED. This work is the stable checkpoint committed
before starting Phase B.

THEN (NEXT, Phase B -- full-suite exploit-and-document-every-vuln): the ONLY
thing still stopping multi-service runs is directive Rule 1 ("STOP EXPLOITING"
at first root). Plan: (1) runtime closes a root session after it auto-documents,
so it stops triggering Rule 1/2 and the directive falls through to the next
untried service; (2) replace Rule 1 -- a rooted service is auto-documented, move
on; (3) add a terminal rule: complete() only when every service is documented/
skipped (reads service_state), not at first root; (4) privesc escape -- a user
shell that cannot escalate after N tries is marked skipped + closed; (5) rewrite
prompts.py workflow from "IF ROOT: stop+complete" to "document + continue".
Needs its own live verification (Metasploitable has several root vectors:
vsftpd, samba usermap, distccd, UnrealIRCd). See backlog item B below.

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