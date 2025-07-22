import xml.etree.ElementTree as ET
import json
from pathlib import Path

def parse_nmap_xml(xml_file: str):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []
    for port in root.findall(".//port"):
        port_id = port.attrib["portid"]
        protocol = port.attrib["protocol"]
        service = port.find("service")
        service_name = service.attrib.get("name", "")
        product = service.attrib.get("product", "")
        version = service.attrib.get("version", "")
        results.append({
            "port": port_id,
            "protocol": protocol,
            "service": service_name,
            "product": product,
            "version": version
        })
    return results

# Placeholder: parse plain text output for other tools if needed
def parse_tool_output(txt_file: str):
    try:
        with open(txt_file, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading {txt_file}: {e}"

def enrich(nmap_file: str, masscan_file: str, rustscan_file: str, nikto_file: str, sslyze_file: str, gobuster_file: str):
    return {
        "ports": parse_nmap_xml(nmap_file),
        "masscan": parse_tool_output(masscan_file),
        "rustscan": parse_tool_output(rustscan_file),
        "nikto": parse_tool_output(nikto_file),
        "sslyze": parse_tool_output(sslyze_file),
        "gobuster": parse_tool_output(gobuster_file)
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 7:
        print("Usage: python enrich_results.py <nmap_xml> <masscan_txt> <rustscan_txt> <nikto_txt> <sslyze_txt> <gobuster_txt>")
    else:
        result = enrich(*sys.argv[1:7])
        print(json.dumps(result, indent=2))
