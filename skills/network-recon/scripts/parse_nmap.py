#!/usr/bin/env python3
"""Parse nmap XML output into structured JSON for the SPAIDER pipeline.

Usage:
    python3 parse_nmap.py <nmap_xml_file> [--output <output_json_file>] [--markdown]

If --output is omitted, prints JSON to stdout.
If --markdown is specified, also prints a markdown table to stderr.
"""

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def parse_nmap_xml(xml_path: str) -> dict:
    """Parse an nmap XML file and return structured JSON."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    scan_info = {
        "target": "",
        "timestamp": "",
        "args": root.get("args", ""),
        "scanner": root.get("scanner", "nmap"),
        "version": root.get("version", ""),
    }

    start_time = root.get("start")
    if start_time:
        scan_info["timestamp"] = datetime.fromtimestamp(
            int(start_time), tz=timezone.utc
        ).isoformat()

    hosts = []

    for host_elem in root.findall("host"):
        host = {"address": "", "hostname": "", "state": "", "ports": []}

        addr_elem = host_elem.find("address")
        if addr_elem is not None:
            host["address"] = addr_elem.get("addr", "")
            if scan_info["target"] == "":
                scan_info["target"] = host["address"]

        # Collect additional addresses (e.g. IPv6, MAC) that nmap may report
        extra_addrs = []
        for ae in host_elem.findall("address"):
            addr_type = ae.get("addrtype", "")
            addr_val = ae.get("addr", "")
            if addr_val and addr_val != host["address"]:
                extra_addrs.append({"addr": addr_val, "addrtype": addr_type})
        if extra_addrs:
            host["additional_addresses"] = extra_addrs

        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                host["hostname"] = hostname_elem.get("name", "")

        status_elem = host_elem.find("status")
        if status_elem is not None:
            host["state"] = status_elem.get("state", "")

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", ""),
                    "state": "",
                    "service": "",
                    "product": "",
                    "version": "",
                    "scripts": [],
                }

                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port["state"] = state_elem.get("state", "")

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port["service"] = service_elem.get("name", "")
                    port["product"] = service_elem.get("product", "")
                    port["version"] = service_elem.get("version", "")

                for script_elem in port_elem.findall("script"):
                    port["scripts"].append(
                        {
                            "id": script_elem.get("id", ""),
                            "output": script_elem.get("output", ""),
                        }
                    )

                host["ports"].append(port)

        hosts.append(host)

    return {"scan_info": scan_info, "hosts": hosts}


def to_markdown_table(scan_result: dict) -> str:
    """Convert scan results to a markdown table for deliverables."""
    lines = ["| Port | Protocol | State | Service | Product | Version |"]
    lines.append("|------|----------|-------|---------|---------|---------|")

    for host in scan_result.get("hosts", []):
        for port in host.get("ports", []):
            lines.append(
                f"| {port['port']} | {port['protocol']} | {port['state']} "
                f"| {port['service']} | {port['product']} | {port['version']} |"
            )

    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: parse_nmap.py <nmap_xml_file> [--output <output_json>] [--markdown]", file=sys.stderr)
        sys.exit(1)

    xml_path = sys.argv[1]

    output_path = None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_path = sys.argv[idx + 1]

    show_markdown = "--markdown" in sys.argv

    try:
        result = parse_nmap_xml(xml_path)
    except FileNotFoundError:
        print(f"Error: file not found: {xml_path}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: invalid XML: {e}", file=sys.stderr)
        sys.exit(1)
    json_str = json.dumps(result, indent=2)

    if output_path:
        with open(output_path, "w") as f:
            f.write(json_str)
        print(f"Written to {output_path}", file=sys.stderr)
    else:
        print(json_str)

    if show_markdown:
        print("\n--- Markdown Table ---", file=sys.stderr)
        print(to_markdown_table(result), file=sys.stderr)


if __name__ == "__main__":
    main()
