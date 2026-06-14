"""In-process pub/sub bus the agent emits telemetry through.

Single-writer (the orchestrator) fans out to many short-lived SSE readers.
Built to the contract the dashboard expects: emit(type, payload, engagement_id)
plus subscribe()/unsubscribe(). Kept dependency-free so the agent layer can
import it without pulling in Flask.
"""

import queue
import threading
import time

# Per-subscriber buffer. Bounds memory if a browser tab stalls while the agent
# keeps emitting. Oldest-drop is preferable to blocking the agent loop.
_MAX_QUEUED = 1000


class EventBus:
    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUED)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def emit(self, type: str, payload, engagement_id: str | None = None) -> None:
        event = {
            "type": type,
            "payload": payload,
            "engagement_id": engagement_id,
            "ts": time.time(),
        }
        # Copy under lock, deliver outside it so a slow put never holds up emit.
        with self._lock:
            targets = list(self._subscribers)
        for q in targets:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Drop for this one slow reader rather than stall the agent.
                pass


# Shared instance the whole app imports.
bus = EventBus()
