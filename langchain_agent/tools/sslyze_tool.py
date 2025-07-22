from sslyze import ServerNetworkLocation, ServerScanRequest, Scanner
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerFailed
import json
import socket
from langchain_core.tools import tool
import subprocess
from pathlib import Path

@tool
def run_sslyze(target: str) -> dict:
    """
    Run SSLyze scan on target (e.g., "scanme.nmap.org:443"). Returns both output and output file path.
    """
    try:
        import shutil
        import socket
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use SSLyze.", "file": None}
        ports_to_try = [443, 8443, 9443, 10443, 4433]
        host, port = (target.split(':')[0], None)
        try:
            ip_host = socket.gethostbyname(host)
        except Exception:
            ip_host = host  # fallback to original host (sslyze may accept hostnames)
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_sslyze.txt"
        if ':' in target:
            try:
                port = int(target.split(':')[1])
                ports_to_try = [port] + [p for p in ports_to_try if p != port]
            except Exception:
                return {"output": "Error: target must be in form hostname:port", "file": None}
        errors = []
        for port in ports_to_try:
            cmd = ["docker", "run", "--rm", "nablac0d3/sslyze:latest", f"{ip_host}:{port}"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n[stderr]\n" + result.stderr)
            except FileNotFoundError:
                return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use SSLyze.", "file": None}
            except subprocess.TimeoutExpired:
                return {"output": "Error: SSLyze scan timed out.", "file": None}
            except Exception as e:
                return {"output": f"Error: SSLyze (Docker) failed to start: {e}", "file": None}
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    file_content = f.read()
            except Exception as e:
                file_content = f"[ERROR] Could not read output file: {e}"
            if result.returncode == 0 and file_content.strip():
                return {"output": file_content, "file": str(output_file)}
            else:
                errors.append(f"sslyze (Docker) failed for {ip_host}:{port}: {result.stderr}")
        return {"output": "All attempted SSL ports failed.\n" + "\n".join(errors), "file": str(output_file)}
    except Exception as e:
        return {"output": f"sslyze (Docker) exception: {e}", "file": None}