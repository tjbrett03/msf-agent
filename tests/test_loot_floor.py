"""
Loot capture floor tests. _capture_loot must record loot from command output
regardless of model behavior. No live target, Ollama, or Metasploit required.
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


class TestLootFloor(unittest.TestCase):

    def setUp(self):
        # Isolate each test's loot by using a unique target IP per case, since the
        # shared temp DB persists across tests in the file.
        self.emitted = []
        self.emit = lambda etype, payload: self.emitted.append((etype, payload))

    def _creds(self, target):
        return memory.read("credential", target).get("rows", [])

    def _findings(self, target):
        return memory.query("finding", {"host_ip": target}).get("rows", [])

    def test_shadow_hashes_persisted_as_credentials(self):
        target = "10.9.0.1"
        output = (
            "root:$1$abc$xyz:18000:0:99999:7:::\n"
            "msfadmin:$1$def$uvw:18000:0:99999:7:::\n"
        )
        result = orchestrator._capture_loot(output, target, self.emit)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["credentials"], 2)

        creds = self._creds(target)
        users = {c["username"] for c in creds}
        self.assertEqual(users, {"root", "msfadmin"})

    def test_ordinary_colon_output_writes_no_credentials(self):
        target = "10.9.0.2"
        output = "Tasks: 5\nMem: 100\nCpu: 12%\nbob: hello there"
        result = orchestrator._capture_loot(output, target, self.emit)
        self.assertEqual(result["credentials"], 0)
        self.assertEqual(self._creds(target), [])

    def test_private_key_records_finding_not_credential(self):
        target = "10.9.0.3"
        output = (
            "found a key:\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        result = orchestrator._capture_loot(output, target, self.emit)
        self.assertEqual(result["credentials"], 0)
        self.assertGreaterEqual(result["findings"], 1)
        self.assertEqual(self._creds(target), [])

        findings = self._findings(target)
        self.assertTrue(any("private key" in f["title"].lower() for f in findings))

    def test_aws_key_records_finding(self):
        target = "10.9.0.4"
        output = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = orchestrator._capture_loot(output, target, self.emit)
        self.assertGreaterEqual(result["findings"], 1)

        findings = self._findings(target)
        self.assertTrue(any("AWS access key" in f["title"] for f in findings))

    def test_loot_findings_are_runtime_confirmed(self):
        target = "10.9.0.5"
        output = "AKIAIOSFODNN7EXAMPLE"
        orchestrator._capture_loot(output, target, self.emit)
        findings = self._findings(target)
        self.assertTrue(findings)
        # The trust split: runtime-captured loot is ground truth.
        for f in findings:
            self.assertEqual(f["source"], "runtime")
            self.assertEqual(f["confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
