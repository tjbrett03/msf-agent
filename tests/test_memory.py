"""
Standalone tests for tools/memory.py. No live target or Metasploit required.
Uses a temp file database so tests don't pollute the real agent.db.
"""
import os
import sys
import tempfile
import unittest

# Point at a throwaway DB for every test run
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

# Repo root must be on path so imports resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tools.memory as memory


class TestMemoryHost(unittest.TestCase):
    def test_write_and_read_host(self):
        result = memory.write("host", {"ip": "10.0.0.1", "os_guess": "Linux"})
        self.assertEqual(result["status"], "ok")

        result = memory.read("host", "10.0.0.1")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["ip"], "10.0.0.1")
        self.assertEqual(result["rows"][0]["os_guess"], "Linux")

    def test_duplicate_host_is_ignored(self):
        memory.write("host", {"ip": "10.0.0.2"})
        memory.write("host", {"ip": "10.0.0.2"})
        result = memory.read("host", "10.0.0.2")
        self.assertEqual(len(result["rows"]), 1)

    def test_read_missing_host_returns_empty(self):
        result = memory.read("host", "10.99.99.99")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [])


class TestMemoryPort(unittest.TestCase):
    def test_write_and_read_port(self):
        memory.write("port", {
            "host_ip": "10.0.0.1", "port": 22, "service": "ssh", "version": "OpenSSH 7.4"
        })
        result = memory.read("port", "10.0.0.1")
        self.assertEqual(result["status"], "ok")
        ports = [r["port"] for r in result["rows"]]
        self.assertIn(22, ports)

    def test_port_upsert_updates_version(self):
        memory.write("port", {"host_ip": "10.0.0.1", "port": 80, "service": "http", "version": "Apache 2.2"})
        memory.write("port", {"host_ip": "10.0.0.1", "port": 80, "service": "http", "version": "Apache 2.4"})
        result = memory.read("port", "10.0.0.1")
        row_80 = next(r for r in result["rows"] if r["port"] == 80)
        self.assertEqual(row_80["version"], "Apache 2.4")


class TestMemoryTriedModule(unittest.TestCase):
    def test_write_tried_module(self):
        result = memory.write("tried_module", {
            "host_ip": "10.0.0.1",
            "port":    22,
            "module":  "exploit/unix/ssh/test",
            "result":  "failed",
            "detail":  "no session created",
        })
        self.assertEqual(result["status"], "ok")

    def test_query_tried_module_by_host(self):
        memory.write("tried_module", {
            "host_ip": "10.0.0.1",
            "port":    445,
            "module":  "exploit/windows/smb/ms17_010",
            "result":  "success",
        })
        result = memory.query("tried_module", {"host_ip": "10.0.0.1"})
        self.assertEqual(result["status"], "ok")
        modules = [r["module"] for r in result["rows"]]
        self.assertIn("exploit/windows/smb/ms17_010", modules)

    def test_query_tried_module_by_host_and_module(self):
        result = memory.query("tried_module", {
            "host_ip": "10.0.0.1",
            "module":  "exploit/windows/smb/ms17_010",
        })
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["rows"]), 1)

    def test_query_tried_module_not_found(self):
        result = memory.query("tried_module", {
            "host_ip": "10.0.0.1",
            "module":  "exploit/does/not/exist",
        })
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [])


class TestMemoryFinding(unittest.TestCase):
    def test_write_finding(self):
        result = memory.write("finding", {
            "host_ip":  "10.0.0.1",
            "port":     21,
            "title":    "Anonymous FTP login allowed",
            "severity": "high",
            "evidence": "logged in as anonymous",
        })
        self.assertEqual(result["status"], "ok")

    def test_read_finding(self):
        memory.write("finding", {
            "host_ip":  "10.0.0.1",
            "port":     23,
            "title":    "Telnet enabled",
            "severity": "medium",
        })
        result = memory.read("finding", "10.0.0.1")
        titles = [r["title"] for r in result["rows"]]
        self.assertIn("Telnet enabled", titles)


class TestMemoryCredential(unittest.TestCase):
    def test_write_credential(self):
        result = memory.write("credential", {
            "host_ip":  "10.0.0.1",
            "service":  "ftp",
            "username": "msfadmin",
            "password": "msfadmin",
            "source":   "brute_force",
        })
        self.assertEqual(result["status"], "ok")

    def test_read_credential(self):
        memory.write("credential", {
            "host_ip":  "10.0.0.1",
            "service":  "ssh",
            "username": "root",
            "password": "toor",
        })
        result = memory.read("credential", "10.0.0.1")
        users = [r["username"] for r in result["rows"]]
        self.assertIn("root", users)


class TestMemoryErrorHandling(unittest.TestCase):
    def test_unknown_category_read_returns_error(self):
        result = memory.read("nonexistent", "key")
        self.assertEqual(result["status"], "error")
        self.assertIn("unknown category", result["error"])

    def test_unknown_category_write_returns_error(self):
        result = memory.write("nonexistent", {"foo": "bar"})
        self.assertEqual(result["status"], "error")

    def test_unknown_category_query_returns_error(self):
        result = memory.query("nonexistent")
        self.assertEqual(result["status"], "error")

    def test_query_no_filters_returns_all(self):
        result = memory.query("finding")
        self.assertEqual(result["status"], "ok")
        self.assertIsInstance(result["rows"], list)


if __name__ == "__main__":
    unittest.main()
