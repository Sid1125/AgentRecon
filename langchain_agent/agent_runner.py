import json
import importlib
import re
from pathlib import Path
from datetime import datetime
from langchain_core.tools import Tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langchain_agent.utils.fuzzy_tool_matcher import match_tool
from langchain_agent.memory.history_manager import add_record, get_last_scan, get_last_target, get_last_result_for_target, get_all_results_for_target, get_last_workflow_for_target, get_last_summary_for_target, set_summary_for_target
from mcp_server.workflow_manager import workflow_manager

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Add a module-level variable to store the last used target
last_used_target = None


def log_to_file(content: str, filename_prefix: str = "agent"):
    # No-op or minimal logging; remove chat history and full prompt logging
    pass


def load_registered_tools(registry_path: str = None) -> list[Tool]:
    tools = []
    registry_file = registry_path or Path(__file__).parent / "tools" / "registry.json"
    with open(registry_file, "r") as f:
        registry = json.load(f)
    for entry in registry:
        try:
            module_path, attr_name = entry["import_path"].rsplit(".", 1)
            module = importlib.import_module(module_path)
            tool_obj = getattr(module, attr_name)
            tools.append(tool_obj)
        except Exception as e:
            print(f"[!] Failed to load {entry['name']}: {str(e)}")
    return tools


def create_agent():
    tools = load_registered_tools()
    llm = ChatOllama(
        model="mistral-nemo:latest",
        system="You are a cybersecurity assistant named AgentRecon made by Siddharth Sinha. Format all scan results in Markdown and explain them clearly. List possible vulnerabilities and do web search as well on those if possible."
    )
    return create_react_agent(llm, tools)


def extract_target(prompt: str, last_target: str = None) -> str:
    """
    Extract target (domain/IP) from a prompt with high reliability.
    Handles various formats and edge cases, including subdomains like s.amizone.net.
    If no target is found in the prompt, uses last_target as fallback.
    """
    import re
    import ipaddress
    # Remove code blocks and inline code
    prompt = re.sub(r'```[\s\S]*?```', '', prompt)  # Remove triple-backtick code blocks
    prompt = re.sub(r'`[^`]+`', '', prompt)           # Remove inline code
    prompt = prompt.strip()

    # Enhanced domain patterns - more comprehensive to catch subdomains
    domain_patterns = [
        # Pattern 1: Full domain with subdomains (like s.amizone.net)
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b',
        # Pattern 2: Simple domain matching
        r'\b([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})\b',
        # Pattern 3: Basic domain
        r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b'
    ]

    # IP address pattern (strict)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    # Try each domain pattern
    for pattern in domain_patterns:
        domains = re.findall(pattern, prompt)
        for domain in reversed(domains):
            # Validate domain: must have at least one dot, not look like a method call, and TLD at least 2 chars
            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$', domain) and not domain.endswith('.'):
                # Exclude common code/method call patterns
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$', domain):
                    return domain

    # Look for IP addresses
    ips = re.findall(ip_pattern, prompt)
    for ip in reversed(ips):
        try:
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue

    # Special case: look for common target keywords
    words = prompt.split()
    for word in reversed(words):
        clean_word = re.sub(r'[^\w\.\-]', '', word).lower()
        if clean_word in ['localhost', 'target', 'host']:
            return clean_word

    # Use last_target as fallback if available
    if last_target:
        return last_target

    return ""


def _handle_tool_calls(tool_call_str, tool_map):
    import json
    import re
    # Extract the JSON part from [TOOL_CALLS][{...}]
    match = re.search(r'\[TOOL_CALLS\]\s*(\[.*\])', tool_call_str)
    if not match:
        return tool_call_str  # fallback: return as is
    try:
        calls = json.loads(match.group(1))
        if not isinstance(calls, list):
            calls = [calls]
    except Exception:
        return tool_call_str
    results = []
    for call in calls:
        name = call.get('name')
        args = call.get('arguments', {})
        tool = tool_map.get(name)
        if not tool:
            results.append(f"Error: Tool '{name}' not found.")
            continue
        try:
            result = tool.invoke(args)
            results.append(result)
        except Exception as e:
            results.append(f"Error executing tool '{name}': {str(e)}")
    return '\n\n'.join(results)


def llm_classify_workflow(prompt: str) -> str:
    """Use the LLM to classify which workflow type is most appropriate for the given prompt."""
    system_msg = (
        "You are a cybersecurity assistant named AgentRecon made by Siddharth Sinha."
        "Given the following user request, choose the most appropriate workflow type for a security scan, unless directly stated which tool to run. "
        "Available workflows: quick_scan, full_recon, web_scan, network_discovery, vulnerability_assessment, ssl_audit. "
        "Respond with only the workflow type."
    )
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": prompt}
    ]
    agent = create_agent()
    result = agent.invoke({"messages": messages})
    workflow_type = result["messages"][-1].content.strip().split()[0]  # Take first word in case of extra text
    return workflow_type


def summarize_findings(target: str) -> str:
    # Try to get the last summary
    summary = get_last_summary_for_target(target)
    if summary:
        return summary
    # If no summary, generate one from all results
    recs = get_all_results_for_target(target)
    if not recs:
        return f"No results found for {target}."
    # Concatenate outputs for LLM summarization
    all_outputs = "\n\n".join([f"[{r['tool']}]\n{r['output'][:2000]}" for r in recs if r.get('output')])
    if not all_outputs.strip():
        return f"No results found for {target}."
    # Use LLM to summarize
    system_msg = (
        f"You are a cybersecurity assistant. Summarize the key findings, vulnerabilities, and risks discovered for the target '{target}' based on the following scan and workflow outputs. Be concise but thorough."
    )
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": all_outputs}
    ]
    agent = create_agent()
    result = agent.invoke({"messages": messages})
    summary = result["messages"][-1].content.strip()
    set_summary_for_target(target, summary)
    return summary


def run_prompt(prompt: str):
    global last_used_target
    # Context-aware commands
    prompt_lower = prompt.lower().strip()
    if prompt_lower.startswith("what did we find out on "):
        target = prompt_lower.replace("what did we find out on ", "").strip()
        return summarize_findings(target)
    if prompt_lower.startswith("show last scan for "):
        target = prompt_lower.replace("show last scan for ", "").strip()
        rec = get_last_scan(target)
        if rec:
            return f"Last scan for {target} (tool: {rec['tool']}, time: {rec['timestamp']}):\n\n{rec['output']}"
        else:
            return f"No previous scan found for {target}."
    if prompt_lower.startswith("show all results for "):
        target = prompt_lower.replace("show all results for ", "").strip()
        recs = get_all_results_for_target(target)
        if recs:
            return "\n\n".join([f"[{r['timestamp']}] {r['tool']}\n{r['output'][:500]}..." for r in recs])
        else:
            return f"No results found for {target}."
    if prompt_lower.startswith("repeat last scan on "):
        target = prompt_lower.replace("repeat last scan on ", "").strip()
        rec = get_last_scan(target)
        if rec and rec.get('tool'):
            tool = rec['tool']
            workflow = rec.get('workflow')
            if workflow:
                return workflow_manager.execute_workflow_sync(target, workflow)
            else:
                tool_map = {t.name: t for t in load_registered_tools()}
                if tool in tool_map:
                    return tool_map[tool].invoke({"target": target})
                else:
                    return f"Tool {tool} not found."
        else:
            return f"No previous scan found for {target}."
    # Check if this is a workflow request first
    workflow_type = workflow_manager.detect_workflow_intent(prompt)
    if not workflow_type:
        workflow_type = llm_classify_workflow(prompt)
        # Minimal debug: print workflow type only if classified by LLM
        print(f"[INFO] LLM classified workflow: {workflow_type}")
    if workflow_type and workflow_manager.should_use_workflow(prompt):
        target = extract_target(prompt, last_used_target)
        if not target:
            target = get_last_target()
            if not target:
                return "Error: Could not determine target from the command. Please specify a valid domain or IP address."
        last_used_target = target
        last_wf = get_last_workflow_for_target(target)
        if last_wf == workflow_type:
            return f"This workflow ({workflow_type}) was already run for {target}. Use 'repeat last scan on {target}' to force rerun, or 'show last scan for {target}' to see results."
        print(f"[INFO] Detected workflow request: {workflow_type} for target {target}")
        result = workflow_manager.execute_workflow_sync(target, workflow_type)
        add_record(prompt, workflow_type, target, result, workflow=workflow_type)
        return result
    matched_tool = match_tool(prompt)
    # Minimal debug: print matched tool only if found
    if matched_tool:
        print(f"[DEBUG] Matched tool: {matched_tool}")
    tool_map = {t.name: t for t in load_registered_tools()}
    prompt_lower = prompt.lower()
    direct_tool_match = matched_tool in tool_map and (matched_tool in prompt_lower.split() or matched_tool in prompt_lower)
    if direct_tool_match:
        target = extract_target(prompt, last_used_target)
        if not target:
            target = get_last_target()
            if not target:
                return "Error: Could not determine target from the command. Please specify a valid domain or IP address."
        last_used_target = target
        last_tool = get_last_result_for_target(target, tool=matched_tool)
        if last_tool:
            return f"This tool ({matched_tool}) was already run for {target}. Use 'repeat last scan on {target}' to force rerun, or 'show last scan for {target}' to see results."
        try:
            params = {"target": target}
            if matched_tool == "nmap":
                params.update({
                    "scan_type": "default",
                    "ports": None,
                    "timing": "T4",
                    "scripts": None,
                    "os_detection": False,
                    "service_info": True,
                    "version_detection": True,
                    "aggressive": False
                })
            elif matched_tool == "masscan":
                params.update({"ports": "1-65535"})
            elif matched_tool == "rustscan":
                params.update({"ports": "1-65535"})
            params = {k: v for k, v in params.items() if v is not None}

            raw_output = tool_map[matched_tool].invoke(params)
            add_record(prompt, matched_tool, target, raw_output)
            if raw_output is None or raw_output == "":
                return f"Error: Tool {matched_tool} returned no output."
            return raw_output
        except Exception as e:
            return f"Error executing tool: {str(e)}"

    # For all other prompts, respond via LLM (skip scan/task logic)
    agent = create_agent()
    messages = [
        {"role": "system", "content": "You are a cybersecurity assistant."},
        {"role": "user", "content": prompt}
    ]
    result = agent.invoke({"messages": messages})
    output = result["messages"][-1].content
    # Intercept [TOOL_CALLS] and execute tool(s) if present
    if output.strip().startswith("[TOOL_CALLS]"):
        tool_result = _handle_tool_calls(output, tool_map)
        add_record(prompt, "TOOL_CALL", None, tool_result)
        log_to_file(f"PROMPT:\n{prompt}\nMATCHED TOOL:\n{matched_tool}\nRAW RESPONSE:\n{tool_result}", "agent_output")
        return tool_result
    add_record(prompt, "LLM", None, output)
    log_to_file(f"PROMPT:\n{prompt}\nMATCHED TOOL:\n{matched_tool}\nRAW RESPONSE:\n{output}", "agent_output")
    return output


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python agent_runner.py \"your prompt here\"")
    else:
        result = run_prompt(sys.argv[1])
        print(result)