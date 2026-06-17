"""
Phase 4 hardening tests. Each class covers one priority fix.
No live target, Ollama, or Metasploit required.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
import orchestrator
import tools.intel as intel
import tools.memory as memory
import tools.sessions as sessions


# ---------------------------------------------------------------------------
# Priority 1: memory_write accepts list for port category
# ---------------------------------------------------------------------------

class TestMemoryWritePortList(unittest.TestCase):

    def test_write_single_port_dict_still_works(self):
        result = memory.write("port", {
            "host_ip": "10.1.0.1", "port": 22, "service": "ssh", "version": "OpenSSH 7.4",
        })
        self.assertEqual(result["status"], "ok")
        rows = memory.read("port", "10.1.0.1")["rows"]
        self.assertTrue(any(r["port"] == 22 for r in rows))

    def test_write_list_of_ports_all_persisted(self):
        ports = [
            {"host_ip": "10.1.0.2", "port": 21, "service": "ftp",  "version": "vsftpd 2.3.4"},
            {"host_ip": "10.1.0.2", "port": 80, "service": "http", "version": "Apache 2.2"},
            {"host_ip": "10.1.0.2", "port": 22, "service": "ssh",  "version": "OpenSSH 4.7"},
        ]
        result = memory.write("port", ports)
        self.assertEqual(result["status"], "ok")

        rows = memory.read("port", "10.1.0.2")["rows"]
        written_ports = {r["port"] for r in rows}
        self.assertEqual(written_ports, {21, 80, 22})

    def test_write_list_upserts_existing_port(self):
        memory.write("port", {"host_ip": "10.1.0.3", "port": 443, "service": "https", "version": "old"})
        memory.write("port", [{"host_ip": "10.1.0.3", "port": 443, "service": "https", "version": "new"}])
        rows = memory.read("port", "10.1.0.3")["rows"]
        row = next(r for r in rows if r["port"] == 443)
        self.assertEqual(row["version"], "new")

    def test_write_empty_list_returns_ok(self):
        result = memory.write("port", [])
        self.assertEqual(result["status"], "ok")


# ---------------------------------------------------------------------------
# Priority 2: WAL mode — concurrent read/write does not deadlock
# ---------------------------------------------------------------------------

class TestWalMode(unittest.TestCase):

    def test_wal_journal_mode_is_set(self):
        # Verify that connections made through _connect() are in WAL mode.
        # Raw sqlite3.connect() on a new file shows 'delete' until WAL is
        # explicitly set, which is why we test via our own _connect().
        from tools.memory import _connect
        conn = _connect()
        row = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        self.assertEqual(row[0], "wal")

    def test_read_after_write_same_connection_cycle(self):
        # Write and read in rapid succession via separate _connect() calls —
        # the pattern that triggered "database is locked" in the live run.
        memory.write("host", {"ip": "10.2.0.1", "os_guess": "Linux"})
        memory.write("port", {"host_ip": "10.2.0.1", "port": 21, "service": "ftp"})
        result = memory.read("port", "10.2.0.1")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(len(result["rows"]) >= 1)


# ---------------------------------------------------------------------------
# Priority 3: unified memory_read accepts optional filters
# ---------------------------------------------------------------------------

class TestUnifiedMemoryRead(unittest.TestCase):

    def setUp(self):
        memory.write("tried_module", {
            "host_ip": "10.3.0.1", "port": 21,
            "module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "result": "ok", "detail": "session opened",
        })
        memory.write("tried_module", {
            "host_ip": "10.3.0.1", "port": 445,
            "module": "exploit/windows/smb/ms17_010",
            "result": "failed", "detail": "no session",
        })

    def test_read_by_key_no_filters(self):
        result = memory.read("tried_module", "10.3.0.1")
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(len(result["rows"]), 2)

    def test_read_with_filters_narrows_results(self):
        result = memory.read("tried_module", "10.3.0.1",
                             filters={"module": "exploit/unix/ftp/vsftpd_234_backdoor"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["module"], "exploit/unix/ftp/vsftpd_234_backdoor")

    def test_read_with_filters_no_match_returns_empty(self):
        result = memory.read("tried_module", "10.3.0.1",
                             filters={"module": "exploit/does/not/exist"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [])

    def test_memory_query_still_works_for_backward_compat(self):
        result = memory.query("tried_module", {"host_ip": "10.3.0.1"})
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(len(result["rows"]), 1)

    def test_dispatch_memory_read_with_filters(self):
        # Verify the orchestrator routes filters through correctly.
        result = orchestrator._dispatch("memory_read", {
            "category": "tried_module",
            "key": "10.3.0.1",
            "filters": {"module": "exploit/unix/ftp/vsftpd_234_backdoor"},
        })
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["rows"]), 1)


# ---------------------------------------------------------------------------
# Priority 4: run_module fast-fail on missing host_ip
# ---------------------------------------------------------------------------

class TestRunModuleMissingHostIp(unittest.TestCase):

    def test_missing_host_ip_returns_structured_error(self):
        result = orchestrator._dispatch("run_module", {
            "port":   21,
            "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        })
        self.assertEqual(result["status"], "error")
        self.assertIn("missing required field", result["error"])
        self.assertIn("host_ip", result["error"])

    def test_empty_host_ip_returns_structured_error(self):
        result = orchestrator._dispatch("run_module", {
            "host_ip": "",
            "port":    21,
            "module":  "exploit/unix/ftp/vsftpd_234_backdoor",
        })
        self.assertEqual(result["status"], "error")
        self.assertIn("missing required field", result["error"])

    def test_present_host_ip_reaches_scope_check(self):
        # A present but out-of-scope IP should hit the scope error, not the
        # fast-fail, proving we only fast-fail on missing/empty.
        # Derive an IP that is guaranteed to be outside the configured scope.
        out_of_scope = next(
            ip for ip in ["198.51.100.1", "203.0.113.1", "192.0.2.1"]
            if ip not in config.AUTHORIZED_SCOPE
        )
        result = orchestrator._dispatch("run_module", {
            "host_ip": out_of_scope,
            "port":    21,
            "module":  "exploit/unix/ftp/vsftpd_234_backdoor",
        })
        self.assertEqual(result["status"], "error")
        self.assertIn("not in authorized scope", result["error"])


# ---------------------------------------------------------------------------
# Priority 5: re-scan stuck detection
# ---------------------------------------------------------------------------

class TestScanStuckDetection(unittest.TestCase):

    @patch("ollama.Client.chat")
    @patch("tools.recon.scan_ports")
    def test_duplicate_scan_injects_warning(self, mock_scan, mock_chat):
        mock_scan.return_value = {
            "status": "ok", "target": config.AUTHORIZED_SCOPE[0], "open_ports": [],
        }
        target = config.AUTHORIZED_SCOPE[0]

        def _make_tc(name, arguments):
            tc = MagicMock()
            tc.function.name = name
            tc.function.arguments = arguments
            msg = MagicMock()
            msg.tool_calls = [tc]
            msg.content = ""
            resp = MagicMock()
            resp.message = msg
            return resp

        mock_chat.side_effect = [
            _make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            _make_tc("scan_ports", {"target": target, "ports": "1-1024"}),  # duplicate
            _make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        # The duplicate scan is blocked, not just warned about: the real scan
        # only ran once and the steering is folded into a tool-role result (a
        # user message would split the assistant tool_calls from its result).
        self.assertEqual(mock_scan.call_count, 1)
        third_call_messages = mock_chat.call_args_list[2][1]["messages"]
        tool_msgs = [m for m in third_call_messages if m["role"] == "tool"]
        self.assertTrue(
            any("already have port data" in m["content"] for m in tool_msgs),
            msg=f"No block notice found in tool messages: {tool_msgs}",
        )

    @patch("ollama.Client.chat")
    @patch("tools.recon.scan_ports")
    def test_non_duplicate_scan_does_not_inject_warning(self, mock_scan, mock_chat):
        mock_scan.return_value = {
            "status": "ok", "target": config.AUTHORIZED_SCOPE[0], "open_ports": [],
        }
        target = config.AUTHORIZED_SCOPE[0]

        def _make_tc(name, arguments):
            tc = MagicMock()
            tc.function.name = name
            tc.function.arguments = arguments
            msg = MagicMock()
            msg.tool_calls = [tc]
            msg.content = ""
            resp = MagicMock()
            resp.message = msg
            return resp

        mock_chat.side_effect = [
            _make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            _make_tc("scan_ports", {"target": target, "ports": "1025-65535"}),  # different args
            _make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        third_call_messages = mock_chat.call_args_list[2][1]["messages"]
        user_msgs = [m for m in third_call_messages if m["role"] == "user"]
        self.assertFalse(
            any("already have port data" in m["content"] for m in user_msgs),
        )


# ---------------------------------------------------------------------------
# Fix 1: Session cleanup at engagement start
# ---------------------------------------------------------------------------

class TestSessionCleanup(unittest.TestCase):

    @patch("ollama.Client.chat")
    @patch("tools.sessions.close_session")
    @patch("tools.sessions.list_sessions")
    def test_pre_existing_sessions_are_closed(self, mock_list, mock_close, mock_chat):
        mock_list.return_value = {
            "status": "ok",
            "count": 2,
            "sessions": {"1": {}, "2": {}},
        }
        mock_close.return_value = {"status": "ok", "closed": True}

        tc = MagicMock()
        tc.function.name = "complete"
        tc.function.arguments = {"summary": "done"}
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        mock_chat.return_value = resp

        orchestrator.run(config.AUTHORIZED_SCOPE[0])

        self.assertEqual(mock_close.call_count, 2)
        closed_ids = {call.args[0] for call in mock_close.call_args_list}
        self.assertEqual(closed_ids, {"1", "2"})

    @patch("ollama.Client.chat")
    @patch("tools.sessions.close_session")
    @patch("tools.sessions.list_sessions")
    def test_no_sessions_does_not_call_close(self, mock_list, mock_close, mock_chat):
        mock_list.return_value = {"status": "ok", "count": 0, "sessions": {}}

        tc = MagicMock()
        tc.function.name = "complete"
        tc.function.arguments = {"summary": "done"}
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        mock_chat.return_value = resp

        orchestrator.run(config.AUTHORIZED_SCOPE[0])

        mock_close.assert_not_called()

    @patch("ollama.Client.chat")
    @patch("tools.sessions.close_session")
    @patch("tools.sessions.list_sessions")
    def test_list_sessions_error_does_not_crash_run(self, mock_list, mock_close, mock_chat):
        mock_list.return_value = {"status": "error", "error": "msfrpcd unavailable"}

        tc = MagicMock()
        tc.function.name = "complete"
        tc.function.arguments = {"summary": "done"}
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        mock_chat.return_value = resp

        result = orchestrator.run(config.AUTHORIZED_SCOPE[0])

        self.assertEqual(result["status"], "complete")
        mock_close.assert_not_called()


# ---------------------------------------------------------------------------
# Fix 2: Stuck detection normalization
# ---------------------------------------------------------------------------

class TestScanStuckNormalized(unittest.TestCase):

    def _make_tc(self, name, arguments):
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = arguments
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        return resp

    @patch("ollama.Client.chat")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.recon.scan_ports")
    def test_different_argument_flag_same_range_triggers_warning(self, mock_scan, _mock_ls, mock_chat):
        mock_scan.return_value = {"status": "ok", "target": config.AUTHORIZED_SCOPE[0], "open_ports": []}
        target = config.AUTHORIZED_SCOPE[0]

        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1000", "arguments": "-sV"}),
            self._make_tc("scan_ports", {"target": target, "ports": "1-1000"}),   # no arguments flag
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        # Same normalized key -> the second scan is blocked, not dispatched.
        self.assertEqual(mock_scan.call_count, 1)
        third_messages = mock_chat.call_args_list[2][1]["messages"]
        tool_msgs = [m for m in third_messages if m["role"] == "tool"]
        self.assertTrue(any("already have port data" in m["content"] for m in tool_msgs))

    @patch("ollama.Client.chat")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.recon.scan_ports")
    def test_rounded_port_ranges_treated_as_same(self, mock_scan, _mock_ls, mock_chat):
        mock_scan.return_value = {"status": "ok", "target": config.AUTHORIZED_SCOPE[0], "open_ports": []}
        target = config.AUTHORIZED_SCOPE[0]

        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1000"}),
            self._make_tc("scan_ports", {"target": target, "ports": "1-1024"}),  # rounds to same 1-1000
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        # Rounds to the same normalized key -> the second scan is blocked.
        self.assertEqual(mock_scan.call_count, 1)
        third_messages = mock_chat.call_args_list[2][1]["messages"]
        tool_msgs = [m for m in third_messages if m["role"] == "tool"]
        self.assertTrue(any("already have port data" in m["content"] for m in tool_msgs))

    @patch("ollama.Client.chat")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.recon.scan_ports")
    def test_third_scan_is_hard_blocked(self, mock_scan, _mock_ls, mock_chat):
        mock_scan.return_value = {"status": "ok", "target": config.AUTHORIZED_SCOPE[0], "open_ports": []}
        target = config.AUTHORIZED_SCOPE[0]

        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1000"}),
            self._make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            self._make_tc("scan_ports", {"target": target, "ports": "1-65535"}),  # third scan blocked
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        # scan_ports should only have been dispatched twice, not three times
        self.assertEqual(mock_scan.call_count, 2)

        # The fourth call's messages should include the block warning
        fourth_messages = mock_chat.call_args_list[3][1]["messages"]
        user_msgs = [m for m in fourth_messages if m["role"] == "user"]
        self.assertTrue(any("scanned" in m["content"] and "twice" in m["content"] for m in user_msgs))


# ---------------------------------------------------------------------------
# Fix 3: CVE version string normalization
# ---------------------------------------------------------------------------

class TestCveVersionNormalization(unittest.TestCase):
    """Tests for intel._normalize_lookup() directly."""

    def test_vsftpd_prefix_stripped(self):
        svc, ver = intel._normalize_lookup("ftp", "vsftpd 2.3.4")
        self.assertEqual(svc, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_openssh_prefix_stripped(self):
        svc, ver = intel._normalize_lookup("ssh", "OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0")
        self.assertEqual(svc, "openssh")
        self.assertEqual(ver, "4.7p1")

    def test_apache_httpd(self):
        svc, ver = intel._normalize_lookup("http", "Apache httpd 2.2.8 (Ubuntu) DAV/2")
        self.assertEqual(svc, "apache")
        self.assertEqual(ver, "2.2.8")

    def test_isc_bind_vendor_prefix_skipped(self):
        svc, ver = intel._normalize_lookup("domain", "ISC BIND 9.4.2")
        self.assertEqual(svc, "bind")
        self.assertEqual(ver, "9.4.2")

    def test_samba_version_range(self):
        svc, ver = intel._normalize_lookup("netbios-ssn", "Samba smbd 3.X - 4.X workgroup: WORKGROUP")
        self.assertEqual(svc, "samba")
        self.assertEqual(ver, "3")

    def test_linux_telnetd_vendor_prefix_skipped(self):
        svc, ver = intel._normalize_lookup("telnet", "Linux telnetd")
        self.assertEqual(svc, "telnetd")
        self.assertEqual(ver, "")

    def test_empty_version_returns_service_unchanged(self):
        svc, ver = intel._normalize_lookup("ftp", "")
        self.assertEqual(svc, "ftp")
        self.assertEqual(ver, "")

    @patch("tools.intel.requests.get")
    def test_lookup_cves_uses_normalized_terms(self, mock_get):
        mock_get.return_value = MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"vulnerabilities": []}),
        )
        intel.lookup_cves("ftp", "vsftpd 2.3.4")
        call_params = mock_get.call_args[1]["params"]
        # The keyword must match what _normalize_lookup derives, not a hardcoded string.
        # This way the assertion stays correct if normalization logic changes.
        expected_svc, expected_ver = intel._normalize_lookup("ftp", "vsftpd 2.3.4")
        expected_keyword = f"{expected_svc} {expected_ver}".strip()
        self.assertEqual(call_params["keywordSearch"], expected_keyword)


# ---------------------------------------------------------------------------
# Session auto-write: root detection and DB write on session open
# ---------------------------------------------------------------------------

class TestSessionAutoWrite(unittest.TestCase):
    """When run_module opens a session, the orchestrator auto-runs 'id',
    writes the session to the DB with the correct username, and no longer
    injects a 'Do NOT call complete()' reminder into the message history."""

    def _make_tc(self, name, arguments):
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = arguments
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        return resp

    @patch("tools.sessions.warm_up", return_value={"status": "ok", "ready": True})
    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_root_detected_via_id(self, mock_run, _ls, mock_cmd, mock_chat, _sleep, _warm):
        """uid=0 in 'id' output -> session written with username=root."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/autowrite_root_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "autoroot1", "host_ip": target, "port": 21, "module": module,
        }
        mock_cmd.return_value = {
            "status": "ok", "output": "uid=0(root) gid=0(root) groups=0(root)",
        }
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        rows = memory.query("session", {"host_ip": target}).get("rows", [])
        root_rows = [r for r in rows if r.get("msf_id") == "autoroot1" and r.get("username") == "root"]
        self.assertTrue(len(root_rows) >= 1, msg=f"Expected root session row, got: {rows}")

    @patch("tools.sessions.warm_up", return_value={"status": "ok", "ready": True})
    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_root_detected_via_whoami_fallback(self, mock_run, _ls, mock_cmd, mock_chat, _sleep, _warm):
        """id returns empty; whoami returns 'root' -> session written with username=root."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/whoami_fallback_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "whoami1", "host_ip": target, "port": 21, "module": module,
        }
        # id returns no uid=0; whoami returns root. The runtime no longer sweeps
        # the host on a root shell (enumeration is model-driven now), so answer by
        # command to stay robust to whatever commands the runtime probes with.
        def cmd_side(_sid, command, *a, **k):
            if command == "id":
                return {"status": "ok", "output": ""}
            if command == "whoami":
                return {"status": "ok", "output": "root\n"}
            return {"status": "ok", "output": ""}  # enum commands, no output
        mock_cmd.side_effect = cmd_side
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        rows = memory.query("session", {"host_ip": target}).get("rows", [])
        root_rows = [r for r in rows if r.get("msf_id") == "whoami1" and r.get("username") == "root"]
        self.assertTrue(len(root_rows) >= 1, msg=f"Expected root via whoami, got: {rows}")

    @patch("tools.sessions.warm_up", return_value={"status": "ok", "ready": True})
    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_model_dumps_shadow_loot_floor_captures_credentials(self, mock_run, _ls, mock_cmd, mock_chat, _sleep, _warm):
        """Enumeration is model-driven now: the model opens a root shell, then
        itself runs 'cat /etc/shadow', and the runtime loot floor captures the
        hashes into the credential table (the runtime no longer auto-sweeps)."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/enum_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "enum1", "host_ip": target, "port": 21, "module": module,
        }

        shadow = "root:$6$abc$realhash:19000:0:99999:7:::\ndaemon:*:18000::::::\nmsfadmin:$1$old$md5hash:14685:0:99999:7:::"
        def cmd_side(_sid, command, *a, **k):
            if command == "id":
                return {"status": "ok", "output": "uid=0(root) gid=0(root)"}
            if command == "cat /etc/shadow":
                return {"status": "ok", "output": shadow}
            return {"status": "ok", "output": ""}
        mock_cmd.side_effect = cmd_side
        # The model itself dumps /etc/shadow; the loot floor on run_command output
        # is what persists the hashes, not any runtime enumeration sweep.
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("run_command", {"session_id": "enum1", "command": "cat /etc/shadow"}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        # Only real hashes persist; the '*' locked daemon account is skipped.
        creds = memory.query("credential", {"host_ip": target}).get("rows", [])
        users = {c["username"]: c["hash"] for c in creds}
        self.assertIn("root", users)
        self.assertIn("msfadmin", users)
        self.assertNotIn("daemon", users)
        self.assertEqual(users["root"], "$6$abc$realhash")

    @patch("tools.sessions.warm_up", return_value={"status": "ok", "ready": True})
    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_unknown_written_when_id_fails(self, mock_run, _ls, mock_cmd, mock_chat, _sleep, _warm):
        """id errors and whoami is not root -> session written with username=unknown."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/autowrite_fail_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "autofail1", "host_ip": target, "port": 21, "module": module,
        }
        # both id and whoami fail to confirm root
        mock_cmd.side_effect = [
            {"status": "error", "error": "timeout"},
            {"status": "ok", "output": "daemon\n"},
        ]
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        rows = memory.query("session", {"host_ip": target}).get("rows", [])
        fail_rows = [r for r in rows if r.get("msf_id") == "autofail1"]
        self.assertTrue(len(fail_rows) >= 1, msg=f"Expected session row, got: {rows}")
        self.assertEqual(fail_rows[0]["username"], "unknown")

    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_no_do_not_call_complete_reminder(self, mock_run, _ls, mock_cmd, mock_chat, _sleep):
        """No 'Do NOT call complete()' message is ever injected into history."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/no_legacy_reminder_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [
            {"host_ip": target, "port": 21,  "service": "ftp", "version": "vsftpd 2.3.4"},
            {"host_ip": target, "port": 445, "service": "smb", "version": "Samba 3.x"},
        ])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "noreminder1", "host_ip": target, "port": 21, "module": module,
        }
        mock_cmd.return_value = {"status": "ok", "output": "uid=0(root) gid=0(root)"}
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        # Check all messages across all chat calls for the legacy reminder text.
        for call in mock_chat.call_args_list:
            for m in call[1]["messages"]:
                self.assertNotIn(
                    "Do NOT call complete()",
                    m.get("content", ""),
                    msg="Legacy reminder still present in message history",
                )


# ---------------------------------------------------------------------------
# Fix 1: Engagement table clear on run start
# ---------------------------------------------------------------------------

class TestEngagementClear(unittest.TestCase):
    """Stale DB data from a prior run is deleted before the loop starts."""

    def _make_tc(self, name, arguments):
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = arguments
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        return resp

    @patch("ollama.Client.chat")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    def test_stale_data_cleared_at_run_start(self, _ls, mock_chat):
        """Port and tried_module data from a prior run are gone after run() starts."""
        target = config.AUTHORIZED_SCOPE[0]

        # Simulate leftover data from a prior engagement.
        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "old"}])
        memory.write("tried_module", {
            "host_ip": target, "port": 21,
            "module": "exploit/unix/ftp/stale_module",
            "result": "ok", "detail": "stale",
        })

        mock_chat.return_value = self._make_tc("complete", {"summary": "done"})
        orchestrator.run(target)

        ports  = memory.read("port", target)
        tried  = memory.query("tried_module", {"host_ip": target})
        self.assertEqual(ports["rows"],  [], msg="Port rows should be cleared")
        self.assertEqual(tried["rows"], [], msg="tried_module rows should be cleared")

    def test_clear_does_not_affect_other_ips(self):
        """Clearing one target's data leaves other IP data intact."""
        other_ip = "10.99.0.1"
        memory.write("port", [{"host_ip": other_ip, "port": 80, "service": "http", "version": "1.0"}])

        target = config.AUTHORIZED_SCOPE[0]
        orchestrator._clear_engagement_tables(target)

        rows = memory.read("port", other_ip)["rows"]
        self.assertTrue(any(r["port"] == 80 for r in rows), msg="Other IP data should survive clear")


# ---------------------------------------------------------------------------
# Fix 2: Tool result truncation
# ---------------------------------------------------------------------------

class TestToolResultTruncation(unittest.TestCase):
    """_truncate_result caps large tool results before they go into messages."""

    def test_small_result_returned_unchanged(self):
        result = {"status": "ok", "data": "short value"}
        self.assertEqual(orchestrator._truncate_result(result), json.dumps(result))

    def test_large_result_is_truncated(self):
        result = {"status": "ok", "rows": [{"col": "x" * 200}] * 20}
        s = orchestrator._truncate_result(result)
        self.assertLessEqual(len(s), orchestrator._MAX_TOOL_RESULT_CHARS + 60)
        self.assertIn("truncated", s)

    def test_truncated_result_includes_total_length(self):
        big = {"status": "ok", "data": "y" * 2000}
        s = orchestrator._truncate_result(big)
        self.assertIn("chars total", s)


# ---------------------------------------------------------------------------
# Change 2: build_supervisor_directive covers all 5 rules
# ---------------------------------------------------------------------------

class TestBuildSupervisorDirective(unittest.TestCase):
    """Tests for orchestrator.build_supervisor_directive -- no DB, no Ollama."""

    TARGET = config.AUTHORIZED_SCOPE[0]

    def _scan_msg(self, target):
        """Return one assistant message containing a scan_ports tool call."""
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "scan_ports", "arguments": {"target": target}}}
            ],
        }

    # --- Rule 1 ---

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule1_root_by_username(self, mock_read, mock_query):
        """Rule 1 fires when a session with username=root is open."""
        def qside(category, filters=None):
            if category == "session":
                return {"status": "ok", "rows": [
                    {"msf_id": "1", "host_ip": self.TARGET,
                     "session_type": "shell", "username": "root", "closed_at": None},
                ]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("STOP EXPLOITING", result)
        self.assertIn("root shell", result)
        self.assertIn("session 1", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule1_root_by_session_type(self, mock_read, mock_query):
        """Rule 1 fires when session_type contains 'root'."""
        def qside(category, filters=None):
            if category == "session":
                return {"status": "ok", "rows": [
                    {"msf_id": "2", "host_ip": self.TARGET,
                     "session_type": "meterpreter_root", "username": "daemon", "closed_at": None},
                ]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("STOP EXPLOITING", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule1_closed_root_session_not_counted(self, mock_read, mock_query):
        """A closed root session does not trigger Rule 1."""
        def qside(category, filters=None):
            if category == "session":
                return {"status": "ok", "rows": [
                    {"msf_id": "3", "host_ip": self.TARGET,
                     "session_type": "shell", "username": "root",
                     "closed_at": "2026-06-04 10:00:00"},
                ]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertNotIn("STOP EXPLOITING", result)

    # --- Rule 2 ---

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule2_user_session(self, mock_read, mock_query):
        """Rule 2 fires when an open non-root session exists."""
        def qside(category, filters=None):
            if category == "session":
                return {"status": "ok", "rows": [
                    {"msf_id": "4", "host_ip": self.TARGET,
                     "session_type": "shell", "username": "www-data", "closed_at": None},
                ]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("user shell", result)
        self.assertIn("privilege escalation", result)
        self.assertIn("session 4", result)

    # --- Rule 3 ---

    @patch("tools.memory.query")
    def test_rule3_untried_ports(self, mock_query):
        """Rule 3 fires when service_state holds ports still marked 'untried'."""
        def qside(category, filters=None):
            if category == "service_state":
                return {"status": "ok", "rows": [
                    {"port": 21, "status": "untried"},
                    {"port": 22, "status": "untried"},
                    {"port": 80, "status": "untried"},
                ]}
            return {"status": "ok", "rows": []}  # no sessions
        mock_query.side_effect = qside

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("Untried services", result)
        self.assertIn("21", result)
        self.assertIn("Do not call complete()", result)

    @patch("tools.memory.query")
    def test_rule3_skipped_when_all_ports_tried(self, mock_query):
        """Rule 3 does not fire when no service_state row is still 'untried'."""
        def qside(category, filters=None):
            if category == "service_state":
                return {"status": "ok", "rows": [{"port": 21, "status": "attempted"}]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertNotIn("Untried services", result)

    # --- Rule 4 ---

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule4_double_scan_detected(self, mock_read, mock_query):
        """Rule 4 fires when the target was scanned twice in the last 6 messages."""
        mock_query.return_value = {"status": "ok", "rows": []}
        mock_read.return_value = {"status": "ok", "rows": []}
        messages = [self._scan_msg(self.TARGET), self._scan_msg(self.TARGET)]

        result = orchestrator.build_supervisor_directive(self.TARGET, messages)
        self.assertIn("already scanned", result)
        self.assertIn("Do not scan again", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule4_single_scan_not_triggered(self, mock_read, mock_query):
        """Rule 4 does not fire with only one scan in history."""
        mock_query.return_value = {"status": "ok", "rows": []}
        mock_read.return_value = {"status": "ok", "rows": []}
        messages = [self._scan_msg(self.TARGET)]

        result = orchestrator.build_supervisor_directive(self.TARGET, messages)
        self.assertNotIn("already scanned", result)

    # --- Rule 5 ---

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule5_default(self, mock_read, mock_query):
        """Rule 5 returns the continue directive when no other rule matches."""
        mock_query.return_value = {"status": "ok", "rows": []}
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertEqual(result, "Continue the engagement.")

    # --- Rule 2 sudo escalation branches ---

    def _open_session_query(self, msf_id="4"):
        """Return a memory.query side-effect that reports one open non-root session."""
        def qside(category, filters=None):
            if category == "session":
                return {"status": "ok", "rows": [
                    {"msf_id": msf_id, "host_ip": self.TARGET,
                     "session_type": "shell", "username": "unknown", "closed_at": None},
                ]}
            return {"status": "ok", "rows": []}
        return qside

    def _tool_msg(self, command, output):
        """Return a tool-role message as the orchestrator appends it."""
        import json as _json
        content = _json.dumps({
            "status": "ok", "session_id": "4",
            "command": command, "output": output,
        })
        return {"role": "tool", "content": content}

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule2_full_sudo_escalates_directive(self, mock_read, mock_query):
        """Rule 2 escalates when (ALL) ALL appears in recent tool messages."""
        mock_query.side_effect = self._open_session_query()
        mock_read.return_value = {"status": "ok", "rows": []}

        messages = [
            self._tool_msg("sudo -l",
                           "User root may run the following commands on this host:\n    (ALL) ALL\n")
        ]
        result = orchestrator.build_supervisor_directive(self.TARGET, messages)
        self.assertIn("full sudo", result)
        self.assertIn("sudo id", result)
        self.assertIn("complete()", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule2_partial_sudo_directive(self, mock_read, mock_query):
        """Rule 2 returns SUID/kernel hint when sudo -l ran but no ALL entry found."""
        mock_query.side_effect = self._open_session_query()
        mock_read.return_value = {"status": "ok", "rows": []}

        messages = [
            self._tool_msg("sudo -l", "Sorry, user daemon may not run sudo on target.\n")
        ]
        result = orchestrator.build_supervisor_directive(self.TARGET, messages)
        self.assertIn("SUID", result)
        self.assertNotIn("already confirmed full sudo", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule2_sudo_not_run_default(self, mock_read, mock_query):
        """Rule 2 returns the try-sudo-l directive when sudo -l has not been run."""
        mock_query.side_effect = self._open_session_query()
        mock_read.return_value = {"status": "ok", "rows": []}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("user shell", result)
        self.assertIn("sudo -l", result)
        self.assertNotIn("full sudo", result)


class TestContextPruning(unittest.TestCase):
    """Context history is pruned to a bounded window so inference does not slow
    and wedge as the message list grows. SQLite + the supervisor directive carry
    the durable state, so dropping old turns is safe."""

    def test_short_history_unchanged(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        self.assertEqual(orchestrator._prune_messages(msgs, 16), msgs)

    def test_keeps_system_and_most_recent(self):
        msgs = [{"role": "system", "content": "sys"}]
        for i in range(40):
            msgs.append({"role": "assistant", "content": f"a{i}"})
            msgs.append({"role": "user", "content": f"u{i}"})
        pruned = orchestrator._prune_messages(msgs, 16)
        self.assertLessEqual(len(pruned), 16)
        self.assertEqual(pruned[0]["content"], "sys")   # system prompt retained
        self.assertEqual(pruned[-1], msgs[-1])           # newest message retained

    def test_no_orphaned_tool_result_at_window_start(self):
        msgs = [{"role": "system", "content": "sys"}]
        for i in range(20):
            msgs.append({"role": "assistant", "content": "call", "tool_calls": [{}]})
            msgs.append({"role": "tool", "content": f"t{i}"})
        pruned = orchestrator._prune_messages(msgs, 6)
        self.assertEqual(pruned[0]["content"], "sys")
        # a 'tool' result must not be the first message after the system prompt
        self.assertNotEqual(pruned[1]["role"], "tool")


class TestEngagementPersistence(unittest.TestCase):
    """A run is a first-class engagement: a row is created at start and finalized
    at the end, findings are scoped to it, events are persisted for replay, and
    findings survive the per-run table clear so past runs stay reviewable."""

    def _make_tc(self, name, arguments):
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = arguments
        msg = MagicMock()
        msg.tool_calls = [tc]
        msg.content = ""
        resp = MagicMock()
        resp.message = msg
        return resp

    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_engagement_row_findings_and_events_persist(self, mock_run, _ls, mock_cmd, mock_chat, _sleep):
        target = config.AUTHORIZED_SCOPE[0]
        eid = "persist-test-eng"
        module = "exploit/unix/ftp/persist_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp"}])
        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "ps1", "host_ip": target, "port": 21, "module": module,
        }
        def cmd_side(_sid, command, *a, **k):
            if command == "id":
                return {"status": "ok", "output": "uid=0(root)"}
            return {"status": "ok", "output": ""}
        mock_cmd.side_effect = cmd_side
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target, eid)

        conn = memory.get_connection()
        try:
            row = conn.execute("SELECT status, ended_at FROM engagement WHERE id = ?", (eid,)).fetchone()
            self.assertIsNotNone(row, "engagement row should exist")
            self.assertEqual(row["status"], "complete")
            self.assertIsNotNone(row["ended_at"])
            fcount = conn.execute("SELECT COUNT(*) FROM finding WHERE engagement_id = ?", (eid,)).fetchone()[0]
            self.assertGreaterEqual(fcount, 1, "findings should be scoped to the engagement")
            ecount = conn.execute("SELECT COUNT(*) FROM event WHERE engagement_id = ?", (eid,)).fetchone()[0]
            self.assertGreater(ecount, 0, "events should be persisted for replay")
        finally:
            conn.close()

    def test_clear_engagement_tables_keeps_findings(self):
        target = config.AUTHORIZED_SCOPE[0]
        memory.write("finding", {"host_ip": target, "title": "keep me", "severity": "info", "engagement_id": "keep"})
        orchestrator._clear_engagement_tables(target)
        rows = memory.read("finding", target).get("rows", [])
        self.assertTrue(any(r["title"] == "keep me" for r in rows),
                        msg="findings must survive the per-run table clear")


class TestFindingsRuntimeOnly(unittest.TestCase):
    """Trust split: the model may author findings (as its own unconfirmed CLAIMS,
    stamped source='model'/confirmed=0), but credentials it cannot hand-write.
    Confirmed FACTS come only from the runtime. See tests/test_trust_split.py for
    the provenance-stamping assertions."""

    def test_model_memory_write_credential_is_blocked(self):
        target = config.AUTHORIZED_SCOPE[0]
        before = len(memory.read("credential", target).get("rows", []))
        res = orchestrator._model_memory_write({
            "category": "credential",
            "data": {"host_ip": target, "username": "root", "password": "made up"},
        })
        self.assertEqual(res["status"], "ok")  # graceful, so the model does not retry-loop
        after = len(memory.read("credential", target).get("rows", []))
        self.assertEqual(before, after, "a model-authored credential must not be persisted")

    def test_other_categories_still_write(self):
        target = config.AUTHORIZED_SCOPE[0]
        res = orchestrator._model_memory_write({
            "category": "tried_module",
            "data": {"host_ip": target, "port": 21, "module": "m/unique_rt", "result": "ok"},
        })
        self.assertEqual(res["status"], "ok")
        rows = memory.query("tried_module", {"host_ip": target, "module": "m/unique_rt"}).get("rows", [])
        self.assertEqual(len(rows), 1)


class TestServiceState(unittest.TestCase):
    """Phase A: durable per-service progress that survives context pruning."""

    def test_seed_creates_untried_row(self):
        memory.seed_service_state("10.9.0.1", 21, "ftp", "eng-ss-1")
        rows = memory.read("service_state", "10.9.0.1")["rows"]
        row = next(r for r in rows if r["port"] == 21)
        self.assertEqual(row["status"], "untried")
        self.assertEqual(row["service"], "ftp")

    def test_seed_is_idempotent_and_does_not_regress(self):
        memory.seed_service_state("10.9.0.2", 21, "ftp")
        memory.advance_service_state("10.9.0.2", 21, "exploited", outcome="root shell")
        # A re-scan re-seeds; it must NOT knock the exploited service back to untried.
        memory.seed_service_state("10.9.0.2", 21, "ftp")
        rows = memory.read("service_state", "10.9.0.2")["rows"]
        row = next(r for r in rows if r["port"] == 21)
        self.assertEqual(row["status"], "exploited")
        self.assertEqual(len([r for r in rows if r["port"] == 21]), 1)

    def test_advance_is_forward_only(self):
        memory.seed_service_state("10.9.0.3", 80, "http")
        memory.advance_service_state("10.9.0.3", 80, "exploited", outcome="shell")
        # A later, weaker 'attempted' (e.g. a duplicate module on the same port) loses,
        # and must NOT clobber the meaningful outcome with its noise.
        memory.advance_service_state("10.9.0.3", 80, "attempted", outcome="dup module error")
        row = next(r for r in memory.read("service_state", "10.9.0.3")["rows"] if r["port"] == 80)
        self.assertEqual(row["status"], "exploited")
        self.assertEqual(row["outcome"], "shell")

    def test_advance_refreshes_outcome_when_moving_forward(self):
        memory.seed_service_state("10.9.0.5", 80, "http")
        memory.advance_service_state("10.9.0.5", 80, "attempted", outcome="first try")
        memory.advance_service_state("10.9.0.5", 80, "exploited", outcome="root shell")
        row = next(r for r in memory.read("service_state", "10.9.0.5")["rows"] if r["port"] == 80)
        self.assertEqual(row["status"], "exploited")
        self.assertEqual(row["outcome"], "root shell")

    def test_advance_progresses_through_states(self):
        memory.seed_service_state("10.9.0.4", 445, "smb")
        for st in ("attempted", "exploited", "documented"):
            memory.advance_service_state("10.9.0.4", 445, st)
        row = next(r for r in memory.read("service_state", "10.9.0.4")["rows"] if r["port"] == 445)
        self.assertEqual(row["status"], "documented")

    def test_directive_reads_service_state(self):
        # End to end through the directive: a seeded-but-untried service surfaces.
        target = config.AUTHORIZED_SCOPE[0]
        memory.seed_service_state(target, 23, "telnet")
        directive = orchestrator.build_supervisor_directive(target, [])
        # Only assert it does not crash and reflects untried when nothing else fires;
        # other rules (session) take priority, so guard on the table being read.
        rows = memory.query("service_state", {"host_ip": target}).get("rows", [])
        self.assertTrue(any(r["port"] == 23 and r["status"] == "untried" for r in rows))


class TestCveLookupDedup(unittest.TestCase):
    """AAR gap #3: a repeat lookup_cves is served from cache, not re-fetched."""

    def setUp(self):
        orchestrator._cve_cache.clear()

    @patch("tools.intel.lookup_cves")
    def test_duplicate_lookup_is_cached(self, mock_lookup):
        mock_lookup.return_value = {"status": "ok", "cves": [{"id": "CVE-2011-2523"}]}
        first = orchestrator._dispatch("lookup_cves", {"service": "vsftpd", "version": "2.3.4"})
        second = orchestrator._dispatch("lookup_cves", {"service": "vsftpd", "version": "2.3.4"})
        self.assertEqual(mock_lookup.call_count, 1)  # NVD hit only once
        self.assertEqual(second["cves"], first["cves"])
        self.assertIn("cached", second.get("note", ""))

    @patch("tools.intel.lookup_cves")
    def test_distinct_lookups_not_collapsed(self, mock_lookup):
        mock_lookup.return_value = {"status": "ok", "cves": []}
        orchestrator._dispatch("lookup_cves", {"service": "vsftpd", "version": "2.3.4"})
        orchestrator._dispatch("lookup_cves", {"service": "openssh", "version": "4.7"})
        self.assertEqual(mock_lookup.call_count, 2)

    @patch("tools.intel.lookup_cves")
    def test_error_is_not_cached(self, mock_lookup):
        mock_lookup.return_value = {"status": "error", "error": "nvd timeout"}
        orchestrator._dispatch("lookup_cves", {"service": "vsftpd", "version": "2.3.4"})
        orchestrator._dispatch("lookup_cves", {"service": "vsftpd", "version": "2.3.4"})
        self.assertEqual(mock_lookup.call_count, 2)  # retried, not stuck on the error

    def test_missing_args_returns_error(self):
        res = orchestrator._dispatch("lookup_cves", {"service": "vsftpd"})
        self.assertEqual(res["status"], "error")


class _FakeShell:
    """Minimal stand-in for pymetasploit3 ShellSession: read() echoes the output of
    the last `echo ...` written, so a warm-up probe round-trips like a real shell."""
    def __init__(self, responsive=True):
        self._last = ""
        self._responsive = responsive

    def write(self, data):
        self._last = data

    def read(self):
        if not self._responsive or not self._last:
            return ""
        out = self._last.strip()
        self._last = ""
        if out.startswith("echo "):
            return out[len("echo "):].replace("''", "") + "\n"
        return ""


class TestSessionReliability(unittest.TestCase):
    """run_command/warm_up must never wedge or cascade: a stuck or contended session
    fails cleanly (hard wall-clock bound) and the shell is warmed before first use,
    because a not-ready backdoor shell silently dropped the first probe and stalled
    a whole run. The lock stops a second reader from corrupting the stream."""

    def setUp(self):
        # The hung-call test intentionally leaves the lock held (a real wedge parks
        # the session); reset it so tests stay isolated.
        import threading
        sessions._session_lock = threading.Lock()

    def test_run_command_times_out_when_blocking_call_hangs(self):
        import time as _t
        with patch("tools.sessions._HANG_GRACE", 0), \
             patch("tools.sessions._run_command_blocking", lambda *a, **k: _t.sleep(2)):
            res = sessions.run_command("1", "id", timeout=0)
        self.assertEqual(res["status"], "error")
        self.assertIn("timed out", res["error"])
        self.assertEqual(res["command"], "id")

    def test_run_command_returns_worker_result_when_fast(self):
        fast = {"status": "ok", "session_id": "1", "command": "id", "output": "uid=0(root)"}
        with patch("tools.sessions._run_command_blocking", return_value=fast):
            res = sessions.run_command("1", "id", timeout=5)
        self.assertEqual(res, fast)

    def test_busy_when_lock_already_held(self):
        # Simulate a parked session (prior wedge holds the lock): the next call must
        # report busy instead of starting a competing reader.
        sessions._session_lock.acquire()
        try:
            res = sessions.run_command("1", "id", timeout=5)
        finally:
            sessions._session_lock.release()
        self.assertEqual(res["status"], "error")
        self.assertIn("busy", res["error"])

    def test_warm_up_ready_when_shell_round_trips(self):
        fake_client = MagicMock()
        fake_client.sessions.session.return_value = _FakeShell(responsive=True)
        with patch("tools.sessions._connect", return_value=fake_client), \
             patch("tools.sessions.ShellSession", _FakeShell):
            res = sessions.warm_up("1", timeout=3)
        self.assertTrue(res["ready"])

    def test_warm_up_not_ready_when_shell_silent(self):
        fake_client = MagicMock()
        fake_client.sessions.session.return_value = _FakeShell(responsive=False)
        with patch("tools.sessions._connect", return_value=fake_client), \
             patch("tools.sessions.ShellSession", _FakeShell):
            res = sessions.warm_up("1", timeout=1)
        self.assertFalse(res["ready"])

    def test_split_token_echo_hides_literal(self):
        token = "RDYdeadbeef"
        cmd = sessions._split_token_echo(token)
        self.assertNotIn(token, cmd)          # not in the typed command line
        self.assertEqual(cmd.replace("''", "").split()[-1], token)  # but prints it


class TestEnumerateSession(unittest.TestCase):
    """The demoted `enumerate` scaffolding tool: a fixed battery of commands run
    via run_command, returning combined labeled output. Unknown category errors."""

    @patch("tools.sessions.run_command")
    def test_system_category_combines_outputs(self, mock_cmd):
        def cmd_side(_sid, command, *a, **k):
            return {"status": "ok", "output": f"out:{command}"}
        mock_cmd.side_effect = cmd_side

        res = sessions.enumerate_session("7", "system")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["category"], "system")
        # Each command's output is present in the combined section blob.
        self.assertIn("out:uname -a", res["output"])
        self.assertIn("out:cat /etc/issue", res["output"])
        self.assertIn("out:hostname", res["output"])

    @patch("tools.sessions.run_command")
    def test_network_falls_back_when_primary_empty(self, mock_cmd):
        def cmd_side(_sid, command, *a, **k):
            # ip/ss yield nothing on Metasploitable; the fallbacks do.
            if command in ("ip addr", "ss -tlnp"):
                return {"status": "ok", "output": ""}
            return {"status": "ok", "output": f"out:{command}"}
        mock_cmd.side_effect = cmd_side

        res = sessions.enumerate_session("7", "network")
        self.assertEqual(res["status"], "ok")
        self.assertIn("out:ifconfig -a", res["output"])
        self.assertIn("out:netstat -tlnp", res["output"])

    @patch("tools.sessions.run_command")
    def test_unknown_category_returns_error(self, mock_cmd):
        res = sessions.enumerate_session("7", "bogus")
        self.assertEqual(res["status"], "error")
        mock_cmd.assert_not_called()


if __name__ == "__main__":
    unittest.main()
