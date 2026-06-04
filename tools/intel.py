import json
import subprocess

import requests

import config

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
    """
    try:
        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        resp = requests.get(
            _NVD_BASE,
            params={"keywordSearch": f"{service} {version}", "resultsPerPage": 10},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()

        cves = [_extract_cve(v) for v in resp.json().get("vulnerabilities", [])]
        cves.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)

        return {
            "status":  "ok",
            "service": service,
            "version": version,
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
