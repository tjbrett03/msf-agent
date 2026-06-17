"""
Completion fact-check floor tests. The model owns the complete() decision; the
runtime refuses exactly one case: an open shell with no loot captured.
No live target, Ollama, or Metasploit required.
"""
import os
import sys
import tempfile
import unittest

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import orchestrator
import tools.memory as memory


class TestCompletionBlocked(unittest.TestCase):

    def setUp(self):
        # Each test runs against its own target so seeded rows do not bleed across
        # cases sharing the module-level temp DB.
        self.target = f"10.9.0.{self._next_octet()}"

    _octet = [0]

    @classmethod
    def _next_octet(cls):
        cls._octet[0] += 1
        return cls._octet[0]

    def _open_session(self, target):
        memory.write("session", {
            "msf_id":       f"sess-{target}",
            "host_ip":      target,
            "session_type": "shell",
            "username":     "root",
        })

    def test_open_shell_no_loot_refuses(self):
        self._open_session(self.target)
        result = orchestrator._completion_blocked(self.target)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "error")
        self.assertIn("no loot", result["error"])

    def test_open_shell_with_credential_allows(self):
        self._open_session(self.target)
        memory.write("credential", {
            "host_ip":  self.target,
            "service":  "shell",
            "username": "root",
            "password": None,
            "hash":     "$6$abc$def",
            "source":   "/etc/shadow",
        })
        self.assertIsNone(orchestrator._completion_blocked(self.target))

    def test_open_shell_with_loot_finding_allows(self):
        self._open_session(self.target)
        memory.write("finding", {
            "host_ip":  self.target,
            "port":     None,
            "title":    "Loot -- private key in /root/.ssh",
            "severity": "high",
            "evidence": "-----BEGIN RSA PRIVATE KEY-----",
        })
        self.assertIsNone(orchestrator._completion_blocked(self.target))

    def test_no_open_session_allows_even_with_no_loot(self):
        # Documenting vulns without ever popping a shell is a valid completion.
        self.assertIsNone(orchestrator._completion_blocked(self.target))

    def test_closed_session_does_not_block(self):
        memory.write("session", {
            "msf_id":       f"sess-{self.target}",
            "host_ip":      self.target,
            "session_type": "shell",
            "username":     "root",
        })
        # Mark the session closed so it no longer counts as an open shell.
        conn = memory.get_connection()
        try:
            conn.execute(
                "UPDATE session SET closed_at = datetime('now') WHERE host_ip = ?",
                (self.target,),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertIsNone(orchestrator._completion_blocked(self.target))

    def test_breach_finding_is_not_loot(self):
        # The auto breach finding and open-port info findings must NOT count as
        # loot, so an open shell with only those still refuses.
        self._open_session(self.target)
        memory.write("finding", {
            "host_ip":  self.target,
            "port":     21,
            "title":    "Shell session as root via exploit/unix/ftp/vsftpd_234_backdoor",
            "severity": "critical",
            "evidence": "uid=0(root)",
        })
        memory.write("finding", {
            "host_ip":  self.target,
            "port":     80,
            "title":    "Open port 80/tcp http",
            "severity": "info",
            "evidence": "http Apache",
        })
        result = orchestrator._completion_blocked(self.target)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
