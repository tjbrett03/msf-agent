"""
Unit tests for tools/intel.py.
All network and subprocess calls are mocked -- no live NVD requests or
searchsploit invocations are made.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Must be set before any project import so config.DB_PATH is evaluated against
# the temp file, not the real database.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tools.intel as intel


def _nvd_response(vulnerabilities: list) -> MagicMock:
    """Build a fake requests.Response for the NVD API."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "resultsPerPage": len(vulnerabilities),
        "totalResults":   len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    return resp


def _nvd_vuln(cve_id: str, description: str, cvss_v31: float | None = None, cvss_v2: float | None = None) -> dict:
    """Build a minimal NVD vulnerability object."""
    metrics = {}
    if cvss_v31 is not None:
        metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": cvss_v31, "baseSeverity": "CRITICAL"}}]
    if cvss_v2 is not None:
        metrics["cvssMetricV2"] = [{"cvssData": {"baseScore": cvss_v2, "baseSeverity": "HIGH"}}]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": metrics,
        }
    }


def _searchsploit_output(titles: list[str]) -> str:
    """Build fake searchsploit --json stdout."""
    return json.dumps({
        "RESULTS_EXPLOIT": [
            {"Title": t, "Path": f"/path/{t}", "Type": "remote", "EDB-ID": str(i + 1)}
            for i, t in enumerate(titles)
        ]
    })


class TestLookupCves(unittest.TestCase):

    @patch("tools.intel.requests.get")
    def test_happy_path_returns_cves(self, mock_get):
        mock_get.return_value = _nvd_response([
            _nvd_vuln("CVE-2011-2523", "vsftpd backdoor", cvss_v31=9.8),
        ])

        result = intel.lookup_cves("vsftpd", "2.3.4")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2011-2523")
        self.assertEqual(result["cves"][0]["cvss_score"], 9.8)
        self.assertEqual(result["cves"][0]["severity"], "CRITICAL")

    @patch("tools.intel.requests.get")
    def test_results_sorted_by_cvss_descending(self, mock_get):
        mock_get.return_value = _nvd_response([
            _nvd_vuln("CVE-LOW",  "low severity",  cvss_v31=3.1),
            _nvd_vuln("CVE-HIGH", "high severity", cvss_v31=9.8),
            _nvd_vuln("CVE-MED",  "medium",        cvss_v31=6.5),
        ])

        result = intel.lookup_cves("openssl", "1.0.1")

        scores = [c["cvss_score"] for c in result["cves"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-HIGH")

    @patch("tools.intel.requests.get")
    def test_empty_results(self, mock_get):
        mock_get.return_value = _nvd_response([])

        result = intel.lookup_cves("unknownservice", "9.9.9")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["cves"], [])

    @patch("tools.intel.requests.get")
    def test_falls_back_to_cvss_v2_when_v31_missing(self, mock_get):
        mock_get.return_value = _nvd_response([
            _nvd_vuln("CVE-OLD", "old vuln", cvss_v2=7.5),
        ])

        result = intel.lookup_cves("apache", "2.2.0")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cves"][0]["cvss_score"], 7.5)

    @patch("tools.intel.requests.get")
    def test_missing_cvss_does_not_crash(self, mock_get):
        mock_get.return_value = _nvd_response([
            _nvd_vuln("CVE-NOCVSS", "no score available"),
        ])

        result = intel.lookup_cves("something", "1.0")

        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["cves"][0]["cvss_score"])

    @patch("tools.intel.requests.get")
    def test_network_error_returns_error_dict(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.RequestException("connection refused")

        result = intel.lookup_cves("ssh", "7.4")

        self.assertEqual(result["status"], "error")
        self.assertIn("NVD API request failed", result["error"])

    @patch("tools.intel.requests.get")
    def test_service_and_version_passed_as_keyword_search(self, mock_get):
        mock_get.return_value = _nvd_response([])

        intel.lookup_cves("nginx", "1.14.0")

        call_params = mock_get.call_args[1]["params"]
        self.assertIn("nginx", call_params["keywordSearch"])
        self.assertIn("1.14.0", call_params["keywordSearch"])


class TestSearchsploit(unittest.TestCase):

    @patch("tools.intel.subprocess.run")
    def test_happy_path_returns_exploits(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=_searchsploit_output(["vsftpd 2.3.4 Backdoor", "vsftpd 2.3.4 RCE"]),
            returncode=0,
        )

        result = intel.searchsploit("vsftpd 2.3.4")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["exploits"][0]["title"], "vsftpd 2.3.4 Backdoor")

    @patch("tools.intel.subprocess.run")
    def test_empty_results(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"RESULTS_EXPLOIT": []}),
            returncode=0,
        )

        result = intel.searchsploit("unknownservice 9.9.9")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["exploits"], [])

    @patch("tools.intel.subprocess.run")
    def test_not_installed_returns_error(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        result = intel.searchsploit("vsftpd")

        self.assertEqual(result["status"], "error")
        self.assertIn("sudo apt install exploitdb", result["error"])

    @patch("tools.intel.subprocess.run")
    def test_timeout_returns_error(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="searchsploit", timeout=30)

        result = intel.searchsploit("vsftpd")

        self.assertEqual(result["status"], "error")
        self.assertIn("timed out", result["error"])

    @patch("tools.intel.subprocess.run")
    def test_invalid_json_output_returns_error(self, mock_run):
        mock_run.return_value = MagicMock(stdout="not json at all", returncode=0)

        result = intel.searchsploit("vsftpd")

        self.assertEqual(result["status"], "error")
        self.assertIn("not valid JSON", result["error"])

    @patch("tools.intel.subprocess.run")
    def test_exploit_fields_are_extracted(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({
                "RESULTS_EXPLOIT": [{
                    "Title":  "Test Exploit",
                    "Path":   "/usr/share/exploitdb/exploits/unix/remote/17491.rb",
                    "Type":   "remote",
                    "EDB-ID": "17491",
                }]
            }),
            returncode=0,
        )

        result = intel.searchsploit("vsftpd 2.3.4")

        exploit = result["exploits"][0]
        self.assertEqual(exploit["title"],  "Test Exploit")
        self.assertEqual(exploit["path"],   "/usr/share/exploitdb/exploits/unix/remote/17491.rb")
        self.assertEqual(exploit["type"],   "remote")
        self.assertEqual(exploit["edb_id"], "17491")


if __name__ == "__main__":
    unittest.main()
