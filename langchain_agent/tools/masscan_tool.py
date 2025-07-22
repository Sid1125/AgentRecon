from langchain_core.tools import tool
import subprocess
from pathlib import Path

@tool
def run_masscan(target: str, ports: str = None) -> dict:
    """
    Run Masscan on the target IP range or host. Returns both output and output file path.
    """
    try:
        import shutil
        import socket
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Masscan.", "file": None}
        # Resolve domain to IP if needed
        try:
            ip_target = socket.gethostbyname(target)
        except Exception as e:
            return {"output": f"Error: Could not resolve {target} to IP: {e}", "file": None}
        port_arg = ports if ports else "1-1000"
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_masscan.txt"
        container_output_file = f"/mnt/{target}_masscan.txt"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{output_dir}:/mnt",
            "adarnimrod/masscan",
            "-p", port_arg, "--rate", "1000",
            "-oJ", container_output_file, ip_target
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        except FileNotFoundError:
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Masscan.", "file": None}
        except subprocess.TimeoutExpired:
            return {"output": "Error: Masscan scan timed out.", "file": None}
        except Exception as e:
            return {"output": f"Error: Masscan (Docker) failed to start: {e}", "file": None}
        if not output_file.exists():
            return {"output": f"Error: Masscan did not create output file {output_file}", "file": str(output_file)}
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"[ERROR] Could not read output file: {e}"
        if result.returncode != 0:
            return {"output": f"Masscan (Docker) failed: {result.stderr}", "file": str(output_file)}
        if not file_content.strip():
            return {"output": "Error: masscan (Docker) returned no output.", "file": str(output_file)}
        return {"output": file_content, "file": str(output_file)}
    except Exception as e:
        return {"output": f"Masscan (Docker) exception: {e}", "file": None}
