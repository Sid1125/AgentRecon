from langchain_core.tools import tool
from pathlib import Path
import json
from scan_pipeline.run_all_scans import run_all_scans
from scan_pipeline.enrich_results import enrich
from scan_pipeline.false_positive_filter import filter_ports
from scan_pipeline.cve_lookup import lookup

@tool
def run_full_scan(
    target: str,
    nmap: str = None,
    masscan: str = None,
    rustscan: str = None,
    nikto: str = None,
    sslyze: str = None,
    gobuster: str = None
) -> str:
    """Full port + web scan + CVE enrichment on a given IP or domain. Accepts optional precomputed result file paths for each tool."""
    try:
        precomputed = {
            'nmap': nmap,
            'masscan': masscan,
            'rustscan': rustscan,
            'nikto': nikto,
            'sslyze': sslyze,
            'gobuster': gobuster
        }
        precomputed = {k: v for k, v in precomputed.items() if v}
        results = run_all_scans(target, precomputed=precomputed)

        # Track enrichment status
        enrich_status = {}
        enriched = {}
        errors = []
        # Try to enrich each tool output, catch errors
        try:
            enriched = enrich(
                results["nmap"],
                results["masscan"],
                results["rustscan"],
                results["nikto"],
                results["sslyze"],
                results["gobuster"]
            )
            enrich_status["nmap"] = "OK" if enriched.get("ports") else "No ports found or parse error"
            for tool in ["masscan", "rustscan", "nikto", "sslyze", "gobuster"]:
                val = enriched.get(tool)
                if val and not (isinstance(val, str) and val.strip().startswith("Error")):
                    enrich_status[tool] = "OK"
                else:
                    enrich_status[tool] = f"Missing or error: {val[:100] if val else 'No data'}"
        except Exception as e:
            errors.append(f"Enrichment failed: {e}")
            return f"[ERROR] Enrichment failed: {e}"  # Fatal error

        # CVE Lookup for each product:version combo
        cve_status = []
        for port in enriched.get("ports", []):
            product = port.get("product")
            version = port.get("version")
            if product and version:
                try:
                    cves = lookup(product, version)
                    port["cves"] = cves
                    cve_count = len(cves.get("vulners", {}).get("data", {}).get("search", []))
                    cve_status.append(f"Port {port['port']} {product} {version}: {cve_count} CVEs found")
                except Exception as e:
                    port["cves"] = {"error": str(e)}
                    cve_status.append(f"Port {port['port']} {product} {version}: CVE lookup error: {e}")
            else:
                cve_status.append(f"Port {port.get('port', '?')}: No product/version for CVE lookup")

        # Filter out false positives
        try:
            enriched["ports"] = filter_ports(enriched.get("ports", []))
        except Exception as e:
            errors.append(f"False positive filtering failed: {e}")

        # Output formatting
        output = f"## Scan Report for `{target}`\n\n"
        output += "### Enrichment Status\n"
        for tool, status in enrich_status.items():
            output += f"- {tool}: {status}\n"
        if errors:
            output += "\n**Errors:**\n" + "\n".join(errors) + "\n"
        output += "\n### CVE Lookup Status\n"
        for line in cve_status:
            output += f"- {line}\n"
        output += "\n### Port Results\n"
        for port in enriched.get("ports", []):
            output += f"- **Port {port.get('port', '?')} ({port.get('service', '?')})**: {port.get('product', '')} {port.get('version', '')}\n"
            if "cves" in port:
                vulners = port["cves"].get("vulners", {}).get("data", {}).get("search", [])
                cve_ids = [v.get("id") for v in vulners] or ["None found"]
                output += f"    - CVEs: {', '.join(cve_ids)}\n"
            if "cves" in port and "error" in port["cves"]:
                output += f"    - CVE Lookup Error: {port['cves']['error']}\n"
        return output
    except ImportError as e:
        return f"Error: Missing dependency: {str(e)}"
    except Exception as e:
        return f"Full scan failed: {str(e)}"
