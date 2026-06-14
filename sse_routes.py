"""Server-Sent Events stream. One GET /events per browser tab.

Each event goes out with the SSE `event:` field set to its type so the client
can route with addEventListener(type, ...), and a JSON `data:` field carrying
the full {type, payload, engagement_id, ts} envelope.
"""

import json
import queue

from flask import Blueprint, Response, stream_with_context

from event_bus import bus

# Idle gap after which we emit an SSE comment heartbeat. Keeps the connection
# from being reaped by intermediaries and lets us notice a dropped client.
_HEARTBEAT_SECONDS = 15

sse_bp = Blueprint("sse", __name__)


@sse_bp.route("/events")
def events() -> Response:
    def stream():
        q = bus.subscribe()
        try:
            # Tell the browser how long to wait before auto-reconnecting.
            yield "retry: 3000\n\n"
            while True:
                try:
                    event = q.get(timeout=_HEARTBEAT_SECONDS)
                except queue.Empty:
                    yield ": heartbeat\n\n"
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
        finally:
            # Runs when the client disconnects and the generator is closed.
            bus.unsubscribe(q)

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Disable proxy buffering so events flush immediately.
            "X-Accel-Buffering": "no",
        },
    )
