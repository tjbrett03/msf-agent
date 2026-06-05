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

        # The third call's message history should contain the stuck warning.
        third_call_messages = mock_chat.call_args_list[2][1]["messages"]
        user_msgs = [m for m in third_call_messages if m["role"] == "user"]
        self.assertTrue(
            any("already have port data" in m["content"] for m in user_msgs),
            msg=f"No stuck warning found in user messages: {user_msgs}",
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

        third_messages = mock_chat.call_args_list[2][1]["messages"]
        user_msgs = [m for m in third_messages if m["role"] == "user"]
        self.assertTrue(any("already have port data" in m["content"] for m in user_msgs))

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

        third_messages = mock_chat.call_args_list[2][1]["messages"]
        user_msgs = [m for m in third_messages if m["role"] == "user"]
        self.assertTrue(any("already have port data" in m["content"] for m in user_msgs))

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

    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_root_detected_via_id(self, mock_run, _ls, mock_cmd, mock_chat, _sleep):
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

    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_root_detected_via_whoami_fallback(self, mock_run, _ls, mock_cmd, mock_chat, _sleep):
        """id returns empty; whoami returns 'root' -> session written with username=root."""
        target = config.AUTHORIZED_SCOPE[0]
        module = "exploit/unix/ftp/whoami_fallback_unique"

        memory.write("host", {"ip": target})
        memory.write("port", [{"host_ip": target, "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])

        mock_run.return_value = {
            "status": "ok", "session_opened": True,
            "session_id": "whoami1", "host_ip": target, "port": 21, "module": module,
        }
        # id returns no uid=0; whoami returns root
        mock_cmd.side_effect = [
            {"status": "ok", "output": ""},
            {"status": "ok", "output": "root\n"},
        ]
        mock_chat.side_effect = [
            self._make_tc("run_module", {"host_ip": target, "port": 21, "module": module}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        orchestrator.run(target)

        rows = memory.query("session", {"host_ip": target}).get("rows", [])
        root_rows = [r for r in rows if r.get("msf_id") == "whoami1" and r.get("username") == "root"]
        self.assertTrue(len(root_rows) >= 1, msg=f"Expected root via whoami, got: {rows}")

    @patch("time.sleep")
    @patch("ollama.Client.chat")
    @patch("tools.sessions.run_command")
    @patch("tools.sessions.list_sessions", return_value={"status": "ok", "count": 0, "sessions": {}})
    @patch("tools.exploit.run_module")
    def test_unknown_written_when_id_fails(self, mock_run, _ls, mock_cmd, mock_chat, _sleep):
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
    @patch("tools.memory.read")
    def test_rule3_untried_ports(self, mock_read, mock_query):
        """Rule 3 fires when ports are in memory but none have been tried."""
        mock_query.return_value = {"status": "ok", "rows": []}  # no sessions, no tried
        mock_read.return_value = {"status": "ok", "rows": [
            {"port": 21}, {"port": 22}, {"port": 80},
        ]}

        result = orchestrator.build_supervisor_directive(self.TARGET, [])
        self.assertIn("Untried services", result)
        self.assertIn("21", result)
        self.assertIn("Do not call complete()", result)

    @patch("tools.memory.query")
    @patch("tools.memory.read")
    def test_rule3_skipped_when_all_ports_tried(self, mock_read, mock_query):
        """Rule 3 does not fire when every known port already has a tried_module entry."""
        def qside(category, filters=None):
            if category == "tried_module":
                return {"status": "ok", "rows": [{"port": 21}]}
            return {"status": "ok", "rows": []}
        mock_query.side_effect = qside
        mock_read.return_value = {"status": "ok", "rows": [{"port": 21}]}

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


if __name__ == "__main__":
    unittest.main()
