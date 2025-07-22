import subprocess
from langchain_core.tools import tool
from pathlib import Path

@tool
def run_rustscan(target: str, port_range: str = None) -> dict:
    """Run RustScan on the given target and port range. Returns both output and output file path."""
    try:
        import shutil
        import socket
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use RustScan.", "file": None}
        try:
            ip_target = socket.gethostbyname(target)
        except Exception as e:
            return {"output": f"Error: Could not resolve {target} to IP: {e}", "file": None}
        important_ports = "20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,179,389,443,445,465,514,587,631,993,995,1080,1194,1433,1434,1521,1723,2049,2181,2375,2376,2483,2484,3306,3389,3690,4000,5000,5432,5672,5800,5900,6379,7001,7002,8000,8008,8080,8081,8443,8888,9200,9300,11211,15672,27017"
        port_arg = port_range if port_range else important_ports
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_rustscan.txt"
        cmd = ["docker", "run", "--rm", "rustscan/rustscan", "--ports", port_arg, "-a", ip_target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n[stderr]\n" + result.stderr)
        except FileNotFoundError:
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use RustScan.", "file": None}
        except subprocess.TimeoutExpired:
            return {"output": "Error: RustScan scan timed out.", "file": None}
        except Exception as e:
            return {"output": f"Error: RustScan (Docker) failed to start: {e}", "file": None}
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"[ERROR] Could not read output file: {e}"
        if result.returncode != 0:
            return {"output": f"Rustscan (Docker) failed: {result.stderr}", "file": str(output_file)}
        if not file_content.strip():
            return {"output": "Error: rustscan (Docker) returned no output.", "file": str(output_file)}
        return {"output": file_content, "file": str(output_file)}
    except Exception as e:
        return {"output": f"Rustscan (Docker) exception: {e}", "file": None}
