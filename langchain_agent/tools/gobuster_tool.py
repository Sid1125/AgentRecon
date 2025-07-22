import subprocess
from langchain_core.tools import tool
import os
from pathlib import Path


@tool
def run_gobuster(target: str) -> dict:
    """
    Run GoBuster via Docker on a target URL using a mounted wordlist. Returns both output and output file path.
    """
    try:
        import shutil
        if not shutil.which("docker"):
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use GoBuster.", "file": None}
        import os
        host_wordlist = os.path.abspath("wordlists/SecLists/Discovery/Web-Content/common.txt")
        if not os.path.isfile(host_wordlist):
            return {"output": f"Error: Wordlist not found at {host_wordlist}", "file": None}
        output_dir = Path(__file__).parent.parent / ".." / "scan_pipeline" / "output"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{target}_gobuster.txt"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{host_wordlist}:/mnt/wordlist.txt",
            "-v", f"{output_dir}:/mnt/output",
            "ghcr.io/oj/gobuster:latest",
            "dir",
            "-u", target,
            "-w", "/mnt/wordlist.txt",
            "--no-error",
            "-q",
            "-t", "30",
            "--exclude-length", "302"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n[stderr]\n" + result.stderr)
        except FileNotFoundError:
            return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use GoBuster.", "file": None}
        except subprocess.TimeoutExpired:
            return {"output": "Error: GoBuster scan timed out.", "file": None}
        except Exception as e:
            return {"output": f"Error: GoBuster (Docker) failed to start: {e}", "file": None}
        if not output_file.exists():
            return {"output": f"Error: GoBuster did not create output file {output_file}", "file": str(output_file)}
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"[ERROR] Could not read output file: {e}"
        if result.returncode != 0:
            return {"output": f"Gobuster (Docker) failed: {result.stderr.strip()}", "file": str(output_file)}
        if not file_content.strip():
            return {"output": "Error: gobuster returned no output.", "file": str(output_file)}
        return {"output": file_content, "file": str(output_file)}
    except FileNotFoundError:
        return {"output": "Error: Docker is not installed or not in PATH. Please install Docker to use GoBuster.", "file": None}
    except subprocess.TimeoutExpired:
        return {"output": "Error: GoBuster scan timed out.", "file": None}
    except Exception as e:
        return {"output": f"Gobuster exception: {e}", "file": None}