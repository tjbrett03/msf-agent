"""
Trust-split tests: the model may surface CLAIMS but may not author FACTS the
system acts on. These verify the data-model enforcement of that split.

No live target, Ollama, or Metasploit required. Uses a throwaway DB so the real
agent.db is never touched (matches tests/test_memory.py / tests/test_phase4.py).
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


class TestTrustSplit(unittest.TestCase):

    def test_model_credential_write_is_blocked(self):
        # The model must not hand-write credentials: blocked path returns ok with
        # a note (so the model does not loop) and writes NO credential row.
        before = memory.read("credential", "10.7.0.1")["rows"]
        res = orchestrator._model_memory_write({
            "category": "credential",
            "data": {"host_ip": "10.7.0.1", "username": "root", "password": "toor"},
        })
        self.assertEqual(res["status"], "ok")
        self.assertIn("note", res)
        after = memory.read("credential", "10.7.0.1")["rows"]
        self.assertEqual(len(after), len(before))

    def test_model_finding_write_is_unconfirmed_model_source(self):
        res = orchestrator._model_memory_write({
            "category": "finding",
            "data": {
                "host_ip": "10.7.0.2",
                "port": 21,
                "title": "FTP allows anonymous login",
                "severity": "medium",
                "evidence": "230 Login successful",
            },
        })
        self.assertEqual(res["status"], "ok")
        rows = [r for r in memory.read("finding", "10.7.0.2")["rows"]
                if r["title"] == "FTP allows anonymous login"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "model")
        self.assertEqual(rows[0]["confirmed"], 0)

    def test_model_finding_write_does_not_mutate_args(self):
        # Provenance is stamped onto a copy, not the model's args dict.
        data = {"host_ip": "10.7.0.3", "title": "t", "severity": "low"}
        orchestrator._model_memory_write({"category": "finding", "data": data})
        self.assertNotIn("source", data)
        self.assertNotIn("confirmed", data)

    def test_runtime_finding_is_confirmed_runtime_source(self):
        orchestrator._record_finding(
            {
                "host_ip": "10.7.0.4",
                "port": 21,
                "title": "Root shell via vsftpd backdoor",
                "severity": "critical",
                "evidence": "uid=0(root)",
            },
            emit=lambda *a, **k: None,
        )
        rows = [r for r in memory.read("finding", "10.7.0.4")["rows"]
                if r["title"] == "Root shell via vsftpd backdoor"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "runtime")
        self.assertEqual(rows[0]["confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
