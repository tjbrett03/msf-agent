import subprocess
import xml.etree.ElementTree as ET

import config


def scan_ports(target: str, ports: str = "1-1000", arguments: str = "-sV") -> dict:
    """
    Run an nmap scan and return structured results.

    ports: port range string, e.g. "1-65535" or "22,80,443"
    arguments: extra nmap flags, e.g. "-sV -O"
    """
    if target not in config.AUTHORIZED_SCOPE:
        return {
            "status": "error",
            "error":  f"target {target} is not in authorized scope",
        }

    try:
        cmd = [
            "nmap",
            "-p", ports,
            arguments,
            "-oX", "-",  # XML output to stdout
            "--open",
            target,
        ]
        # split the arguments string so subprocess doesn't treat it as one token
        cmd_flat = ["nmap", "-p", ports] + arguments.split() + ["-oX", "-", "--open", target]
        result = subprocess.run(
            cmd_flat,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "error":  result.stderr.strip() or "nmap returned non-zero exit code",
            }

        return _parse_nmap_xml(result.stdout, target)

    except FileNotFoundError:
        return {"status": "error", "error": "nmap not found, install nmap"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "nmap timed out after 300 seconds"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _parse_nmap_xml(xml_output: str, target: str) -> dict:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"status": "error", "error": f"failed to parse nmap XML: {e}"}

    open_ports = []
    for host in root.findall("host"):
        for port_elem in host.findall("ports/port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port_elem.find("service")
            open_ports.append({
                "port":     int(port_elem.get("portid", 0)),
                "protocol": port_elem.get("protocol", "tcp"),
                "state":    "open",
                "service":  service.get("name", "") if service is not None else "",
                "version":  _build_version_string(service) if service is not None else "",
            })

    return {
        "status": "ok",
        "target": target,
        "open_ports": open_ports,
    }


def _build_version_string(service_elem: ET.Element) -> str:
    parts = [
        service_elem.get("product", ""),
        service_elem.get("version", ""),
        service_elem.get("extrainfo", ""),
    ]
    return " ".join(p for p in parts if p).strip()
