# langchain_agent/memory/history_manager.py
import json
from datetime import datetime
from pathlib import Path

HISTORY_FILE = Path(__file__).parent / "recent.json"
MAX_RECORDS = 100   # keep the last 100 interactions

# --- UPGRADED CONTEXT/HISTORY MANAGER ---
def _load_history() -> list[dict]:
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def _save_history(records: list[dict]) -> None:
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(records[-MAX_RECORDS:], f, indent=2)

def add_record(prompt: str, tool: str, target: str, output: str, workflow: str = None, session: str = None, summary: str = None) -> None:
    records = _load_history()
    records.append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "prompt": prompt,
        "tool": tool,
        "target": target,
        "output": output[:10_000],  # truncate huge blobs
        "workflow": workflow,
        "session": session,
        "summary": summary
    })
    _save_history(records)

def set_summary_for_target(target: str, summary: str) -> None:
    records = _load_history()
    for rec in reversed(records):
        if rec.get("target") == target:
            rec["summary"] = summary
            break
    _save_history(records)

def get_last_summary_for_target(target: str) -> str | None:
    records = _load_history()[::-1]
    for rec in records:
        if rec.get("target") == target and rec.get("summary"):
            return rec["summary"]
    return None

def get_last_target() -> str | None:
    records = _load_history()[::-1]
    for rec in records:
        if rec.get("target"):
            return rec["target"]
    return None

def get_last_result_for_target(target: str, tool: str = None, workflow: str = None) -> dict | None:
    records = _load_history()[::-1]
    for rec in records:
        if rec.get("target") == target:
            if tool and rec.get("tool") != tool:
                continue
            if workflow and rec.get("workflow") != workflow:
                continue
            return rec
    return None

def get_all_results_for_target(target: str) -> list[dict]:
    return [rec for rec in _load_history() if rec.get("target") == target]

def get_last_workflow_for_target(target: str) -> str | None:
    records = _load_history()[::-1]
    for rec in records:
        if rec.get("target") == target and rec.get("workflow"):
            return rec["workflow"]
    return None

def get_last_scan(target: str | None = None) -> dict | None:
    # For backward compatibility
    return get_last_result_for_target(target)
