from langchain_core.tools import tool
import subprocess
from typing import Optional
from pathlib import Path


@tool
def run_nmap(
        target: str,
        scan_type: Optional[str] = "default",
        ports: Optional[str] = None,
        timing: Optional[str] = "T4",
        scripts: Optional[str] = None,
        os_detection: Optional[bool] = False,
        service_info: Optional[bool] = True,
        version_detection: Optional[bool] = True,
        aggressive: Optional[bool] = False
) -> dict:
    """Scan a target using Nmap with customizable parameters. Returns both output and output file path."""
    try:
        import shutil
        import socket
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Nmap.", "file": None}
        # Try to resolve the target to an IP (optional, but gives better error messages)
        try:
            ip_target = socket.gethostbyname(target)
        except Exception as e:
            return {"output": f"Error: Could not resolve {target} to IP: {e}", "file": None}
        # Output file path
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_nmap.xml"
        cmd = ["docker", "run", "--rm", "-v", f"{output_dir}:/mnt", "instrumentisto/nmap"]
        if scan_type == "stealth":
            cmd.append("-sS")
        elif scan_type == "aggressive":
            cmd.append("-A")
        elif scan_type == "vuln":
            cmd.extend(["-sV", "--script=vuln"])
        elif scan_type == "discovery":
            cmd.append("-sn")
        else:
            cmd.append("-sS")
        if ports:
            cmd.extend(["-p", ports])
        if timing:
            cmd.append(f"-{timing}")
        if scripts:
            cmd.extend(["--script", scripts])
        if os_detection:
            cmd.append("-O")
        if version_detection:
            cmd.append("-sV")
        if service_info:
            cmd.append("-sC")
        if aggressive:
            cmd.append("-A")
        container_output_path = f"/mnt/{target}_nmap.xml"
        cmd.extend(["-oX", container_output_path, ip_target])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        except FileNotFoundError:
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Nmap.", "file": None}
        except subprocess.TimeoutExpired:
            return {"output": "Error: Nmap scan timed out.", "file": None}
        except Exception as e:
            return {"output": f"Error: Nmap (Docker) failed to start: {e}", "file": None}
        # Read the output file
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"[ERROR] Could not read output file: {e}"
        if result.returncode != 0:
            return {"output": f"Nmap (Docker) failed: {result.stderr}", "file": str(output_file)}
        if not file_content.strip():
            return {"output": "Error: nmap (Docker) returned no output.", "file": str(output_file)}
        return {"output": file_content, "file": str(output_file)}
    except Exception as e:
        return {"output": f"Nmap (Docker) exception: {e}", "file": None}