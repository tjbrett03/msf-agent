"""
Tests for runtime enforcement of the tried_module guard in _dispatch.

Verifies that the orchestrator blocks duplicate run_module calls and
auto-writes tried_module after each execution, independent of model behavior.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
import orchestrator
import tools.memory as memory


TARGET = config.AUTHORIZED_SCOPE[0]
PORT   = 21

# Canned return value for the real exploit.run_module so tests never need
# a live msfrpcd connection.
_MOCK_OK = {"status": "ok", "session_opened": False, "result": "stub"}


def _unique(label: str) -> str:
    return f"exploit/unix/ftp/vsftpd_234_backdoor_{label}"


class TestTriedModuleGuard(unittest.TestCase):

    @patch("tools.exploit.run_module", return_value=_MOCK_OK)
    def test_first_run_allowed(self, _mock):
        """run_module succeeds when no tried_module entry exists for this combination."""
        result = orchestrator._dispatch("run_module", {
            "host_ip": TARGET,
            "port":    PORT,
            "module":  _unique("first_run"),
        })
        self.assertEqual(result["status"], "ok")

    @patch("tools.exploit.run_module", return_value=_MOCK_OK)
    def test_duplicate_run_blocked(self, _mock):
        """run_module returns an error when the same host/port/module has been tried."""
        module = _unique("duplicate")

        first = orchestrator._dispatch("run_module", {
            "host_ip": TARGET, "port": PORT, "module": module,
        })
        self.assertEqual(first["status"], "ok")

        second = orchestrator._dispatch("run_module", {
            "host_ip": TARGET, "port": PORT, "module": module,
        })
        self.assertEqual(second["status"], "error")
        self.assertIn("already tried", second["error"])

    @patch("tools.exploit.run_module", return_value=_MOCK_OK)
    def test_auto_writes_tried_module(self, _mock):
        """orchestrator persists tried_module after run_module executes."""
        module = _unique("auto_write")

        orchestrator._dispatch("run_module", {
            "host_ip": TARGET, "port": PORT, "module": module,
        })

        check = memory.query("tried_module", {
            "host_ip": TARGET, "port": PORT, "module": module,
        })
        self.assertEqual(check["status"], "ok")
        self.assertEqual(len(check["rows"]), 1)
        self.assertEqual(check["rows"][0]["module"], module)

    @patch("tools.exploit.run_module", return_value=_MOCK_OK)
    def test_different_port_allowed(self, _mock):
        """Same module on a different port is not blocked by the guard."""
        module = _unique("diff_port")

        first = orchestrator._dispatch("run_module", {
            "host_ip": TARGET, "port": 21, "module": module,
        })
        self.assertEqual(first["status"], "ok")

        second = orchestrator._dispatch("run_module", {
            "host_ip": TARGET, "port": 80, "module": module,
        })
        self.assertEqual(second["status"], "ok")

    def test_out_of_scope_blocked(self):
        """run_module against an out-of-scope IP is rejected before any DB check."""
        result = orchestrator._dispatch("run_module", {
            "host_ip": "10.0.0.99",
            "port":    PORT,
            "module":  _unique("oos"),
        })
        self.assertEqual(result["status"], "error")
        self.assertIn("not in authorized scope", result["error"])


if __name__ == "__main__":
    unittest.main()
