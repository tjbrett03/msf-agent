"use strict";

// One EventSource for the whole page. The live stream always updates the
// engagement history list, but only repaints the findings/feed/modules panels
// when the user is viewing the live (running) engagement. Viewing a past
// engagement loads a read-only snapshot from /engagement/<id> and ignores live
// events for the panels so the snapshot is not clobbered.

const $ = (id) => document.getElementById(id);
const EVENT_TYPES = [
  "engagement_started",
  "engagement_finished",
  "module_started",
  "module_finished",
  "finding",
  "log",
];

const MAX_RECENT_MODULES = 12;
const MAX_FEED_ROWS = 300;

// view.mode: "live" (panels track the running engagement) or "archived"
// (panels show a frozen past run). view.id is the engagement on screen.
let view = { mode: "live", id: null };
let activeId = null; // the currently running engagement, or null
const engagements = new Map();

function fmtTime(ts) {
  // ts may be a float epoch (events) or a sqlite string (findings/engagements).
  let d;
  if (typeof ts === "number") {
    d = new Date(ts * 1000);
  } else if (typeof ts === "string" && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(ts)) {
    // sqlite datetime('now') is UTC with no zone marker; tag it as UTC so it
    // converts to the viewer's local time instead of being read as local
    // (which showed the wrong time, even the wrong day, near midnight).
    d = new Date(ts.replace(" ", "T") + "Z");
  } else {
    d = new Date(ts);
  }
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleTimeString();
}

function severityClass(sev) {
  return "sev sev-" + String(sev || "info").toLowerCase();
}

function shortId(id) {
  return id && id.length > 8 ? id.slice(0, 8) : id;
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// --- panel renderers ---------------------------------------------------------

function clearPanels() {
  $("feed").innerHTML = "";
  $("findings-body").innerHTML = "";
  $("recent-modules").innerHTML = "";
  setCurrentModule("no module running", false);
}

function appendFeed(type, ev) {
  const feed = $("feed");
  const row = document.createElement("div");
  row.className = "row";
  const detail =
    typeof ev.payload === "string" ? ev.payload : JSON.stringify(ev.payload);
  row.innerHTML =
    `<span class="ts">${fmtTime(ev.ts)}</span>` +
    `<span class="etype">${type}</span>` +
    `<span>${escapeHtml(detail)}</span>`;
  feed.prepend(row);
  while (feed.childElementCount > MAX_FEED_ROWS) feed.lastChild.remove();
}

function setCurrentModule(text, running) {
  const el = $("current-module");
  el.textContent = text;
  el.classList.toggle("running", !!running);
}

function pushRecentModule(name, result) {
  const list = $("recent-modules");
  const li = document.createElement("li");
  const ok = result && /success|ok|session|opened/i.test(result);
  li.innerHTML =
    `<span>${escapeHtml(name)}</span>` +
    `<span class="tag ${ok ? "tag-ok" : "tag-fail"}">${escapeHtml(result || "done")}</span>`;
  list.prepend(li);
  while (list.childElementCount > MAX_RECENT_MODULES) list.lastChild.remove();
}

function addFinding(f) {
  const body = $("findings-body");
  const tr = document.createElement("tr");
  tr.className = "finding-row";
  const sev = f.severity || "info";
  const detail = f.detail || f.title || "";
  const eng = f.engagement_id || f.engagement || "-";
  tr.innerHTML =
    `<td class="${severityClass(sev)}">${escapeHtml(sev)}</td>` +
    `<td>${escapeHtml(detail)}</td>` +
    `<td>${fmtTime(f.ts || f.created_at)}</td>` +
    `<td class="eng-id">${escapeHtml(shortId(eng))}</td>`;
  // Keep the full finding on the row so a click can show its evidence.
  tr._finding = f;
  tr.addEventListener("click", () => openFinding(f));
  body.prepend(tr);
}

// --- finding detail modal ----------------------------------------------------

function openFinding(f) {
  const sev = f.severity || "info";
  $("fm-severity").className = severityClass(sev);
  $("fm-severity").textContent = sev;
  $("fm-title").textContent = f.detail || f.title || "";

  const host = f.host_ip || "?";
  const port = f.port == null ? "" : `:${f.port}`;
  const eng = f.engagement_id || f.engagement;
  const when = fmtTime(f.ts || f.created_at);
  const meta = [`host ${host}${port}`, `time ${when}`];
  if (eng) meta.push(`engagement ${shortId(eng)}`);
  $("fm-meta").textContent = meta.join("   |   ");

  const ev = f.evidence;
  $("fm-evidence").textContent =
    ev == null || ev === "" ? "(no evidence captured)"
      : typeof ev === "string" ? ev
      : JSON.stringify(ev, null, 2);

  $("finding-modal").classList.remove("hidden");
}

function closeFinding() {
  $("finding-modal").classList.add("hidden");
}

// Apply one event to the panels. Used both for the live stream and for replaying
// a past engagement. tableFindings is false during replay because findings come
// from the detail's findings array, so finding events must not double-add them.
function renderEvent(type, ev, tableFindings) {
  appendFeed(type, ev);
  const p = ev.payload || {};
  switch (type) {
    case "module_started":
      setCurrentModule((p.module || "module") + " ...", true);
      break;
    case "module_finished":
      setCurrentModule("no module running", false);
      pushRecentModule(p.module || "module", p.result);
      break;
    case "finding":
      if (tableFindings) {
        addFinding({ ...p, engagement_id: ev.engagement_id, ts: ev.ts });
      }
      break;
  }
}

// --- engagement history list -------------------------------------------------

function renderEngagement(id, target, status) {
  if (!id) return;
  const rec = engagements.get(id) || { id };
  if (target) rec.target = target;
  if (status) rec.status = status;
  engagements.set(id, rec);

  let li = document.getElementById("eng-" + id);
  if (!li) {
    li = document.createElement("li");
    li.id = "eng-" + id;
    li.className = "eng-item";
    // Click a running engagement to resume its live view, a finished one to
    // open its read-only snapshot.
    li.addEventListener("click", () =>
      openEngagement(id, id === activeId ? "live" : "archived")
    );
    $("engagements").prepend(li);
  }
  const cls = rec.status === "running" ? "eng-running" : "eng-done";
  const current = id === view.id ? " viewing" : "";
  li.className = "eng-item" + current;
  li.innerHTML =
    `<span class="eng-id">${escapeHtml(shortId(id))}</span> ` +
    `<span>${escapeHtml(rec.target || "?")}</span>` +
    `<span class="eng-status ${cls}">${escapeHtml(rec.status || "running")}</span>`;
}

function markViewingItem() {
  // Re-render the highlight on the list without refetching.
  for (const [id, rec] of engagements) renderEngagement(id, rec.target, rec.status);
}

// --- view switching ----------------------------------------------------------

async function openEngagement(id, mode) {
  view = { mode, id };
  clearPanels();
  setViewBanner();
  markViewingItem();
  if (!id) return;
  try {
    const res = await fetch(`/engagement/${id}`);
    const data = await res.json();
    if (data.status !== "ok") return;
    (data.findings || []).forEach(addFinding);
    // Events are oldest-first; appendFeed prepends, so the newest ends on top.
    (data.events || []).forEach((ev) => renderEvent(ev.type, ev, false));
    if (data.engagement && data.engagement.status !== "running") {
      setCurrentModule("no module running", false);
    }
  } catch (e) {
    console.warn("load engagement failed", e);
  }
}

function backToLive() {
  if (activeId) {
    openEngagement(activeId, "live");
  } else {
    view = { mode: "live", id: null };
    clearPanels();
    setViewBanner();
    markViewingItem();
  }
}

function setViewBanner() {
  const bar = $("viewbar");
  if (view.mode === "archived") {
    bar.classList.remove("hidden");
    bar.innerHTML =
      `Viewing past engagement <span class="eng-id">${escapeHtml(shortId(view.id))}</span> ` +
      `<button id="back-live" class="secondary">back to live</button>`;
    $("back-live").addEventListener("click", backToLive);
  } else {
    bar.classList.add("hidden");
    bar.innerHTML = "";
  }
}

// --- live event routing ------------------------------------------------------

function onLiveEvent(type, ev) {
  // History list reflects lifecycle no matter what is on screen.
  if (type === "engagement_started") {
    activeId = ev.engagement_id;
    renderEngagement(ev.engagement_id, (ev.payload || {}).target, "running");
  } else if (type === "engagement_finished") {
    renderEngagement(
      ev.engagement_id,
      (ev.payload || {}).target,
      (ev.payload || {}).status || "finished"
    );
    if (activeId === ev.engagement_id) activeId = null;
  }

  // Panels update only while viewing the live engagement.
  if (view.mode === "live" && ev.engagement_id === view.id) {
    renderEvent(type, ev, true);
    if (type === "engagement_finished") setCurrentModule("no module running", false);
  }
}

// --- SSE connection ----------------------------------------------------------

let source = null;

function connect() {
  source = new EventSource("/events");
  source.onopen = () => setConn("connected", "conn-up");
  source.onerror = () => setConn("reconnecting", "conn-wait");
  for (const t of EVENT_TYPES) {
    source.addEventListener(t, (e) => {
      let ev;
      try {
        ev = JSON.parse(e.data);
      } catch {
        return;
      }
      onLiveEvent(t, ev);
    });
  }
}

function setConn(text, cls) {
  const el = $("conn");
  el.textContent = text;
  el.className = "conn " + cls;
}

// --- control actions ---------------------------------------------------------

async function startEngagement() {
  const target = $("target").value.trim();
  if (!target) return;
  const res = await fetch("/engagement/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  const data = await res.json();
  if (data.status !== "ok") {
    alert("start failed: " + (data.error || res.status));
    return;
  }
  // Fresh live view for the new run; events will stream in.
  activeId = data.engagement_id;
  view = { mode: "live", id: data.engagement_id };
  clearPanels();
  setViewBanner();
  renderEngagement(data.engagement_id, target, "running");
}

async function endEngagement() {
  const id = activeId || (view.mode === "live" ? view.id : null);
  if (!id) {
    alert("no running engagement to end");
    return;
  }
  await fetch(`/engagement/${id}/end`, { method: "POST" });
  // engagement_finished will update the status; refresh the history list too.
  refreshHistory();
}

// --- bootstrap ---------------------------------------------------------------

async function refreshHistory() {
  try {
    const data = await (await fetch("/engagements")).json();
    activeId = data.active || null;
    // Newest-first from the API; render reversed so prepend leaves newest on top.
    (data.engagements || [])
      .slice()
      .reverse()
      .forEach((e) => renderEngagement(e.id, e.target, e.status));
  } catch (e) {
    console.warn("refresh history failed", e);
  }
}

async function bootstrap() {
  try {
    const data = await (await fetch("/api/bootstrap")).json();
    activeId = data.active || null;
    (data.engagements || [])
      .slice()
      .reverse()
      .forEach((e) => renderEngagement(e.id, e.target, e.status));
    if (activeId) openEngagement(activeId, "live");
  } catch (e) {
    console.warn("bootstrap failed", e);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("start-btn").addEventListener("click", startEngagement);
  $("end-btn").addEventListener("click", endEngagement);
  $("target").addEventListener("keydown", (e) => {
    if (e.key === "Enter") startEngagement();
  });

  // Finding modal: close via the button, clicking the backdrop, or Escape.
  $("fm-close").addEventListener("click", closeFinding);
  $("finding-modal").addEventListener("click", (e) => {
    if (e.target.id === "finding-modal") closeFinding();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeFinding();
  });

  bootstrap();
  connect();
});
