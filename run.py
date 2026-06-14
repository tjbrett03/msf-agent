#!/usr/bin/env python3
"""Single launcher: preflight the runtime, then serve the dashboard.

Why this exists: a live engagement needs three things outside this process to be
up before the dashboard can do anything useful -- Ollama (the model), msfrpcd
(the Metasploit RPC bridge), and the target host. Starting web_app.py alone
"works", but the first engagement then dies deep in the loop with an opaque
error because one of them is down. This launcher reports the state of all three
up front, starts the one daemon the project actually owns (msfrpcd) if it is
missing, and leaves the rest to their own lifecycles. It deliberately does not
start Ollama (a system service) or the target VM (host-controlled in
VirtualBox); auto-killing either from here would surprise.

Usage:
  python run.py              preflight, start msfrpcd if needed, serve dashboard
  python run.py --check      preflight report only, no side effects, then exit
  python run.py --no-msfrpcd serve without auto-starting msfrpcd
"""

import atexit
import json
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import config

HOST = "127.0.0.1"
PORT = 5000


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """True if a TCP connect to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_ollama() -> tuple[bool, str]:
    """Report Ollama reachability and whether the configured model is pulled.

    A reachable Ollama with the wrong model still fails every engagement at the
    first chat call, so the pulled-model check is worth doing here.
    """
    url = config.OLLAMA_HOST.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            tags = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError):
        return False, f"unreachable at {config.OLLAMA_HOST}"
    names = [m.get("name", "") for m in tags.get("models", [])]
    if config.OLLAMA_MODEL not in names:
        have = ", ".join(names) or "none"
        return False, f"up, but model {config.OLLAMA_MODEL} not pulled (have: {have})"
    return True, f"up, model {config.OLLAMA_MODEL} present"


def check_target(ip: str) -> tuple[bool, str]:
    """Best-effort reachability via one ICMP echo.

    Ping is often filtered, so a failure here is a warning, not a hard stop; the
    port scan settles reachability for real once an engagement starts.
    """
    try:
        rc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
    except FileNotFoundError:
        return False, "ping not available"
    return (rc == 0), ("responds to ping" if rc == 0 else "no ping response")


def _stop_proc(proc: subprocess.Popen) -> None:
    """Terminate a daemon we started, escalating to kill if it ignores SIGTERM."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def ensure_msfrpcd() -> tuple[bool, str]:
    """Start msfrpcd if its port is closed. Returns (ok, detail).

    msfrpcd is the one daemon this project owns, so the launcher manages it. If
    we start it, an atexit handler stops it on shutdown. If it is already up
    (started by hand in another terminal) we leave it alone, since we did not
    open it and should not close it.
    """
    if _tcp_open(config.MSF_HOST, config.MSF_PORT):
        return True, f"already running on {config.MSF_HOST}:{config.MSF_PORT}"

    cmd = [
        "msfrpcd",
        "-P", config.MSF_PASS,
        "-U", config.MSF_USER,
        "-a", config.MSF_HOST,
        "-p", str(config.MSF_PORT),
        # -f keeps msfrpcd in the foreground. Without it msfrpcd daemonizes: it
        # forks the real server and the parent exits 0, so our Popen handle would
        # track the dead parent (misreported as "exited early") and the atexit
        # cleanup would leave the actual daemon orphaned. Foreground ties the
        # daemon's lifetime to this launcher, which is the whole point.
        "-f",
    ]
    # -S disables SSL. config.MSF_SSL defaults false because msfrpcd is started
    # with -S in this project; keep the launcher and the client in agreement.
    if not config.MSF_SSL:
        cmd.append("-S")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        return False, "msfrpcd not found on PATH"

    # msfrpcd loads the whole framework before it binds, so the port can take
    # several seconds to open. Poll for it, and bail early if the process dies.
    for _ in range(30):
        if _tcp_open(config.MSF_HOST, config.MSF_PORT):
            atexit.register(_stop_proc, proc)
            return True, f"started (pid {proc.pid}) on {config.MSF_HOST}:{config.MSF_PORT}"
        if proc.poll() is not None:
            return False, f"exited early (code {proc.returncode})"
        time.sleep(1)
    return False, "started but port did not open within 30s"


def _line(ok: bool, label: str, detail: str, warn: bool = False) -> None:
    tag = "OK  " if ok else ("WARN" if warn else "DOWN")
    print(f"  [{tag}] {label:8} {detail}")


def preflight(start_msf: bool) -> None:
    """Print a go/no-go report for the three external dependencies.

    This never blocks the launch: the dashboard is useful even with daemons down
    (the Start button and the SSE stream still work), so the report just makes
    the state obvious before the first engagement would fail for it.
    """
    print("Preflight:")

    ok, detail = check_ollama()
    _line(ok, "Ollama", detail)

    if start_msf:
        ok_msf, detail = ensure_msfrpcd()
    else:
        up = _tcp_open(config.MSF_HOST, config.MSF_PORT)
        ok_msf, detail = up, ("running" if up else "down (auto-start disabled)")
    _line(ok_msf, "msfrpcd", detail)

    for ip in config.AUTHORIZED_SCOPE:
        ok_t, detail = check_target(ip)
        _line(ok_t, "target", f"{ip}: {detail}", warn=True)


def main() -> None:
    check_only = "--check" in sys.argv
    # --check is side-effect-free, so it never starts msfrpcd.
    start_msf = "--no-msfrpcd" not in sys.argv and not check_only

    # atexit (which stops msfrpcd) runs on normal exit and on Ctrl+C, but NOT on
    # SIGTERM, which terminates the interpreter without unwinding. A programmatic
    # restart or `kill <pid>` would then orphan the msfrpcd we started. Translate
    # SIGTERM into a normal exit so the atexit cleanup fires.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    preflight(start_msf=start_msf)
    if check_only:
        return

    # Imported here so the preflight prints before Flask's banner, and so a
    # --check run does not even need Flask present.
    from web_app import app

    print(f"\nDashboard:  http://{HOST}:{PORT}")
    print(f"Target:     {', '.join(config.AUTHORIZED_SCOPE)}")
    print("Ctrl+C to stop.\n")

    # threaded=True: the SSE endpoint holds a worker for the life of each open
    # browser tab, so the control POSTs would block without it. Matches web_app.
    app.run(host=HOST, port=PORT, threaded=True, debug=False)


if __name__ == "__main__":
    main()
