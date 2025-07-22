import subprocess
from langchain_core.tools import tool
from pathlib import Path

@tool
def run_nikto(target: str) -> dict:
    """Run Nikto using Docker (ghcr.io/sullo/nikto) on a given target. Returns both output and output file path."""
    try:
        import shutil
        import socket
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Nikto.", "file": None}
        try:
            ip_target = socket.gethostbyname(target)
        except Exception:
            ip_target = target  # fallback to original target (Nikto may accept hostnames)
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_nikto.txt"
        cmd = ["docker", "run", "--rm", "-v", f"{output_dir}:/mnt", "ghcr.io/sullo/nikto", "-host", ip_target, "-output", f"/mnt/{target}_nikto.txt", "-errorlimit", "100"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use Nikto.", "file": None}
        except subprocess.TimeoutExpired:
            return {"output": "Error: Nikto scan timed out.", "file": None}
        except Exception as e:
            return {"output": f"Error: Nikto (Docker) failed to start: {e}", "file": None}
        if not output_file.exists():
            return {"output": f"Error: Nikto did not create output file {output_file}", "file": str(output_file)}
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"[ERROR] Could not read output file: {e}"
        if result.returncode != 0:
            return {"output": f"Nikto (Docker) failed: {result.stderr.strip()}", "file": str(output_file)}
        if not file_content.strip():
            return {"output": "Error: Nikto (Docker) returned no output.", "file": str(output_file)}
        if file_content.strip().startswith("Options:"):
            return {"output": "Error: Nikto returned help/options text. Check arguments or target.", "file": str(output_file)}
        return {"output": file_content, "file": str(output_file)}
    except Exception as e:
        return {"output": f"Nikto (Docker) scan failed: {str(e)}", "file": None}
