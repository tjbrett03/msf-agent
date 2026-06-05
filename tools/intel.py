import json
import re
import subprocess

import requests

import config

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Words that appear first in nmap version strings but are not the actual software
# name -- skip them when extracting the software name for NVD lookup.
_VENDOR_PREFIXES = {"isc", "gnu", "linux", "netkit", "mit", "openssl"}


def _normalize_lookup(service: str, version: str) -> tuple[str, str]:
    """
    Normalize nmap service/version strings for better NVD keyword search results.

    nmap version strings often look like:
      "vsftpd 2.3.4"                              -> ("vsftpd", "2.3.4")
      "OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2"  -> ("openssh", "4.7p1")
      "Apache httpd 2.2.8 (Ubuntu) DAV/2"         -> ("apache", "2.2.8")
      "ISC BIND 9.4.2"                            -> ("bind", "9.4.2")
      "Linux telnetd"                             -> ("telnetd", "")

    Returns (normalized_service, version_token) suitable for NVD keyword search.
    """
    if not version:
        return service, version

    words = version.split()

    # Extract software name: first word not in the vendor-prefix list.
    software = service
    for word in words:
        candidate = word.lower().rstrip("-/:()")
        if candidate and re.match(r"^[a-z]", candidate) and candidate not in _VENDOR_PREFIXES:
            software = candidate
            break

    # Extract the first version token: starts with a digit, followed by digits,
    # dots, or a single lowercase letter+digit patch suffix (e.g. "4.7p1").
    version_token = ""
    for word in words:
        m = re.match(r"^(\d+(?:[.\-]\d+)*(?:[a-z]\d+)?)", word)
        if m:
            version_token = m.group(1).rstrip(".")
            break

    return software, version_token


def _extract_cve(vuln: dict) -> dict:
    cve = vuln["cve"]

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "",
    )

    # Prefer CVSSv3.1, fall back to v2.
    score = None
    severity = None
    metrics = cve.get("metrics", {})
    if metrics.get("cvssMetricV31"):
        data = metrics["cvssMetricV31"][0]["cvssData"]
        score    = data.get("baseScore")
        severity = data.get("baseSeverity")
    elif metrics.get("cvssMetricV2"):
        data = metrics["cvssMetricV2"][0]["cvssData"]
        score    = data.get("baseScore")
        severity = data.get("baseSeverity")

    return {
        "cve_id":      cve["id"],
        "description": desc,
        "cvss_score":  score,
        "severity":    severity,
    }


def lookup_cves(service: str, version: str) -> dict:
    """
    Query NVD for CVEs matching service and version.
    Returns up to 10 results sorted by CVSS score descending.
    Normalizes nmap version strings before searching (e.g. "vsftpd 2.3.4" ->
    searches "vsftpd 2.3.4" rather than "ftp vsftpd 2.3.4").
    """
    try:
        normalized_service, normalized_version = _normalize_lookup(service, version)
        keyword = f"{normalized_service} {normalized_version}".strip()

        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        resp = requests.get(
            _NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": 10},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()

        cves = [_extract_cve(v) for v in resp.json().get("vulnerabilities", [])]
        cves.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)

        return {
            "status":  "ok",
            "service": normalized_service,
            "version": normalized_version,
            "count":   len(cves),
            "cves":    cves,
        }

    except requests.RequestException as e:
        return {"status": "error", "error": f"NVD API request failed: {e}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def searchsploit(query: str) -> dict:
    """
    Run the searchsploit CLI and return matching exploits as structured data.
    Returns a descriptive error if searchsploit is not installed.
    """
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True,
            text=True,
            timeout=30,
        )

        data = json.loads(proc.stdout)
        exploits = [
            {
                "title":  e.get("Title", ""),
                "path":   e.get("Path", ""),
                "type":   e.get("Type", ""),
                "edb_id": e.get("EDB-ID", ""),
            }
            for e in data.get("RESULTS_EXPLOIT", [])
        ]

        return {
            "status":   "ok",
            "query":    query,
            "count":    len(exploits),
            "exploits": exploits,
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "error":  "searchsploit not found -- install with: sudo apt install exploitdb",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "searchsploit timed out"}
    except json.JSONDecodeError as e:
        return {"status": "error", "error": f"searchsploit output not valid JSON: {e}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
