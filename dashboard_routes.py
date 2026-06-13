"""Control and read routes for the dashboard.

Control: start/abort an engagement (POST, JSON in/out).
Read:    bootstrap the UI from the SQLite store so it is not empty on load.

The start route enforces scope, mints an engagement_id, and launches
orchestrator.run on a daemon thread inside this process. In-process is required
so the orchestrator emits to the same EventBus the SSE stream (/events) reads
from. abort sets the cooperative cancel flag the loop checks each iteration.
"""

import json
import sqlite3
import threading
import uuid

from flask import Blueprint, jsonify, request

import config
import orchestrator

dashboard_bp = Blueprint("dashboard", __name__)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _engagements_payload() -> dict:
    """The engagement history plus the id of the running one, if any."""
    conn = _connect()
    try:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT id, target, status, started_at, ended_at, summary "
                "FROM engagement ORDER BY datetime(started_at) DESC LIMIT 100"
            ).fetchall()
        ]
    finally:
        conn.close()
    active = orchestrator.active_engagement() or {}
    return {"status": "ok", "engagements": rows, "active": active.get("id")}


@dashboard_bp.route("/api/bootstrap")
def bootstrap():
    """Initial paint: the engagement history and the active engagement id. The
    frontend loads the active (or a selected past) engagement's detail from
    /engagement/<id>. Findings are no longer dumped globally; they are scoped to
    an engagement."""
    return jsonify(_engagements_payload())


@dashboard_bp.route("/engagements")
def list_engagements():
    """Same payload as bootstrap, for refreshing the history after start/end."""
    return jsonify(_engagements_payload())


@dashboard_bp.route("/engagement/<engagement_id>")
def engagement_detail(engagement_id: str):
    """Full snapshot of one engagement: its row, findings, and event log so the
    feed and modules panel can be replayed when a past run is opened."""
    conn = _connect()
    try:
        eng = conn.execute(
            "SELECT id, target, status, started_at, ended_at, summary "
            "FROM engagement WHERE id = ?",
            (engagement_id,),
        ).fetchone()
        if eng is None:
            return jsonify({"status": "error", "error": "engagement not found"}), 404
        findings = [
            dict(r)
            for r in conn.execute(
                "SELECT id, host_ip, port, title, severity, evidence, created_at "
                "FROM finding WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            ).fetchall()
        ]
        events = [
            dict(r)
            for r in conn.execute(
                "SELECT type, payload, ts FROM event WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            ).fetchall()
        ]
    except sqlite3.Error as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    finally:
        conn.close()

    # payload is stored as JSON text; parse so the client gets objects back.
    for ev in events:
        try:
            ev["payload"] = json.loads(ev["payload"]) if ev["payload"] else {}
        except (TypeError, ValueError):
            ev["payload"] = {}

    return jsonify(
        {"status": "ok", "engagement": dict(eng), "findings": findings, "events": events}
    )


@dashboard_bp.route("/engagement/start", methods=["POST"])
def start_engagement():
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"status": "error", "error": "target is required"}), 400

    # Scope enforcement lives in the runtime, never in the model or the browser.
    # Reject out-of-scope targets here before any engagement id is minted.
    if target not in config.AUTHORIZED_SCOPE:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": f"{target} is not in authorized scope",
                    "authorized_scope": config.AUTHORIZED_SCOPE,
                }
            ),
            403,
        )

    engagement_id = str(uuid.uuid4())

    # Refuse to start a second concurrent engagement. orchestrator.run clears all
    # MSF sessions on entry, so a second run would tear down the first one's
    # shell and the two would interleave in the shared tables. claim is atomic,
    # so a double-clicked Start button gets one launch and one 409.
    if not orchestrator.claim_engagement(target, engagement_id):
        active = orchestrator.active_engagement() or {}
        return (
            jsonify(
                {
                    "status": "error",
                    "error": f"an engagement is already running against {active.get('target')}; abort it before starting another",
                    "active": active,
                }
            ),
            409,
        )

    # Run inside this process on a background thread so the orchestrator emits to
    # the same in-process EventBus the SSE stream reads from. daemon=True so the
    # thread never blocks interpreter exit.
    thread = threading.Thread(
        target=_run_engagement,
        args=(target, engagement_id),
        daemon=True,
    )
    thread.start()

    return jsonify(
        {"status": "ok", "engagement_id": engagement_id, "target": target}
    )


def _run_engagement(target: str, engagement_id: str) -> None:
    """Run the engagement, then release the slot no matter how the run ended.

    Pairing release with claim here (rather than inside run) keeps the slot's
    lifecycle in one place and guarantees it frees on complete, abort, or crash.
    """
    try:
        orchestrator.run(target, engagement_id)
    finally:
        orchestrator.release_engagement(engagement_id)


@dashboard_bp.route("/engagement/<engagement_id>/abort", methods=["POST"])
def abort_engagement(engagement_id: str):
    # Cooperative cancel: the orchestrator loop checks this flag each iteration
    # and exits cleanly, emitting engagement_finished. No hard kill.
    orchestrator.request_abort(engagement_id)
    return jsonify(
        {"status": "ok", "engagement_id": engagement_id, "aborting": True}
    )


@dashboard_bp.route("/engagement/<engagement_id>/end", methods=["POST"])
def end_engagement(engagement_id: str):
    """Explicitly close out an engagement. If it is the running one, abort it and
    let the loop's finish() record the terminal status; otherwise it is already
    finished and archiving for review is purely a frontend concern.

    FUTURE: this is the hook where After Action Report generation will kick off
    once the run has stopped.
    """
    active = orchestrator.active_engagement() or {}
    aborting = active.get("id") == engagement_id
    if aborting:
        orchestrator.request_abort(engagement_id)
    return jsonify(
        {"status": "ok", "engagement_id": engagement_id, "aborting": aborting}
    )
