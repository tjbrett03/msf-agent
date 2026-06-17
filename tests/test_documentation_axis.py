"""
Tests for the documentation axis: at scan time the runtime assesses EVERY open
port for known CVEs and records a service_assessment row, automatically and
exhaustively, without the model issuing any lookup_cves call. Documentation is
runtime-owned, so completion never needs a documentation gate.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
# Isolate the DB before importing memory/orchestrator so the schema applies to
# the temp file, matching tests/test_phase4.py.
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import orchestrator
import tools.memory as memory


class TestDocumentationAxis(unittest.TestCase):

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
    @patch("tools.intel.lookup_cves")
    @patch("tools.recon.scan_ports")
    def test_every_open_port_assessed_automatically(self, mock_scan, mock_cves, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]

        # Two ports with distinct (service, version) so the per-run CVE cache
        # does not collapse them into a single lookup.
        mock_scan.return_value = {
            "status": "ok",
            "target": target,
            "open_ports": [
                {"port": 21, "protocol": "tcp", "service": "vsftpd", "version": "2.3.4"},
                {"port": 22, "protocol": "tcp", "service": "openssh", "version": "9.0"},
            ],
        }

        # vsftpd 2.3.4 returns a CVE; openssh 9.0 returns none.
        def _lookup(service, version):
            if service == "vsftpd":
                return {
                    "status": "ok",
                    "count": 1,
                    "cves": [{
                        "cve_id": "CVE-2011-2523",
                        "description": "vsftpd backdoor",
                        "cvss_score": 10.0,
                        "severity": "CRITICAL",
                    }],
                }
            return {"status": "ok", "count": 0, "cves": []}

        mock_cves.side_effect = _lookup

        # The model only scans then completes; it never calls lookup_cves itself.
        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        # The runtime drove every lookup; the model issued zero lookup_cves calls.
        # Two open ports, two distinct services, so exactly two NVD lookups.
        self.assertEqual(mock_cves.call_count, 2)

        ftp = memory.read("service_assessment", target, {"port": 21})["rows"]
        ssh = memory.read("service_assessment", target, {"port": 22})["rows"]
        self.assertEqual(len(ftp), 1)
        self.assertEqual(len(ssh), 1)

        # Vulnerable port: flagged, severity set, CVE id recorded.
        self.assertEqual(ftp[0]["vulnerable"], 1)
        self.assertEqual(ftp[0]["severity"], "CRITICAL")
        self.assertIn("CVE-2011-2523", ftp[0]["cve_ids"] or "")

        # Non-vulnerable port: still documented, but not flagged.
        self.assertEqual(ssh[0]["vulnerable"], 0)

    @patch("ollama.Client.chat")
    @patch("tools.intel.lookup_cves")
    @patch("tools.recon.scan_ports")
    def test_port_without_service_is_still_documented(self, mock_scan, mock_cves, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]

        mock_scan.return_value = {
            "status": "ok",
            "target": target,
            "open_ports": [
                {"port": 5555, "protocol": "tcp", "service": None, "version": None},
            ],
        }
        # No service means no lookup should fire, but the row must still exist.
        mock_cves.side_effect = AssertionError("lookup_cves should not run for a serviceless port")

        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(mock_cves.call_count, 0)

        rows = memory.read("service_assessment", target, {"port": 5555})["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vulnerable"], 0)

    @patch("ollama.Client.chat")
    @patch("tools.intel.lookup_cves")
    @patch("tools.recon.scan_ports")
    def test_lookup_error_records_not_vulnerable_without_aborting(self, mock_scan, mock_cves, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]

        mock_scan.return_value = {
            "status": "ok",
            "target": target,
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "apache", "version": "2.2.8"},
                {"port": 139, "protocol": "tcp", "service": "samba", "version": "3.0.20"},
            ],
        }

        # First port errors (transient NVD), second succeeds. The error must not
        # abort documentation of the second port.
        def _lookup(service, version):
            if service == "apache":
                return {"status": "error", "error": "NVD timeout"}
            return {
                "status": "ok",
                "count": 1,
                "cves": [{
                    "cve_id": "CVE-2007-2447",
                    "description": "samba usermap",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                }],
            }

        mock_cves.side_effect = _lookup

        mock_chat.side_effect = [
            self._make_tc("scan_ports", {"target": target, "ports": "1-1024"}),
            self._make_tc("complete", {"summary": "done"}),
        ]

        result = orchestrator.run(target)
        self.assertEqual(result["status"], "complete")

        apache = memory.read("service_assessment", target, {"port": 80})["rows"]
        samba = memory.read("service_assessment", target, {"port": 139})["rows"]
        self.assertEqual(len(apache), 1)
        self.assertEqual(apache[0]["vulnerable"], 0)  # errored lookup -> not flagged
        self.assertEqual(len(samba), 1)
        self.assertEqual(samba[0]["vulnerable"], 1)


if __name__ == "__main__":
    unittest.main()
