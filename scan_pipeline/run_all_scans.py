import subprocess
import json
import os
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Helper to run a docker command and save output
def run_docker_tool(cmd, output_file):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n[stderr]\n" + result.stderr)
        return str(output_file)
    except Exception as e:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Exception: {e}")
        return str(output_file)

def run_all_scans(target: str, precomputed: dict = None):
    """Collects and returns file paths for all tool outputs for a target. Does not run any tools."""
    precomputed = precomputed or {}
    output_dir = Path(__file__).parent / "output"
    output_dir = output_dir.resolve()
    def default_path(tool, ext):
        return str(output_dir / f"{target}_{tool}.{ext}")
    results = {}
    results["nmap"] = precomputed.get("nmap") or default_path("nmap", "xml")
    results["masscan"] = precomputed.get("masscan") or default_path("masscan", "txt")
    results["rustscan"] = precomputed.get("rustscan") or default_path("rustscan", "txt")
    results["nikto"] = precomputed.get("nikto") or default_path("nikto", "txt")
    results["sslyze"] = precomputed.get("sslyze") or default_path("sslyze", "txt")
    results["gobuster"] = precomputed.get("gobuster") or default_path("gobuster", "txt")
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python run_all_scans.py <target>")
    else:
        target = sys.argv[1]
        print(json.dumps(run_all_scans(target), indent=2))
