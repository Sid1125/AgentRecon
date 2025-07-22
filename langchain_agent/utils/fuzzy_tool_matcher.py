import difflib
import logging

# Define mappings of keywords to tool names (matching registry.json and @tool names)
TOOL_KEYWORDS = {
    "nmap": [
        "port scan", "nmap", "tcp scan", "udp scan", "open ports",
        "os detection", "service detection", "aggressive scan", "vulnerability scan",
        "network discovery", "nmap scripting", "version detection", "scan host",
        "nse scripts", "banner grabbing", "nmap automation"
    ],
    "masscan": [
        "fast port scan", "masscan", "scan large network", "large subnet",
        "scan multiple IPs", "speed scan", "scan thousands of hosts",
        "internet-wide scan", "massive scan", "asynchronous scan", "quick discovery"
    ],
    "nikto": [
        "nikto", "vulnerability scan", "web vuln scan", "http headers",
        "xss", "http methods", "cgi", "server misconfig", "directory traversal",
        "ssl check", "outdated software", "web recon", "apache vulns", "iis issues"
    ],
    "rustscan": [
        "rustscan", "fast scan", "low latency scan", "lightweight port scan",
        "quick scan", "port discover", "stealthy scan", "async scan",
        "scan with nmap", "port pre-scan", "fast enumeration"
    ],
    "sslyze": [
        "ssl", "tls", "certificate", "sslyze", "heartbleed",
        "cipher suite", "ssl scan", "https analysis", "cert check",
        "ssl vulnerability", "weak ciphers", "tls version", "ocsp", "cert expiry",
        "ssl protocol support", "scan ssl config"
    ],
    "run_gobuster": [
        "file enumeration", "directory brute force", "gobuster", "dirbust",
        "hidden files", "dir scan", "web fuzz", "resource discovery",
        "directory scan", "bruteforce web paths", "virtual host scan", "dns fuzz",
        "subdirectory enumeration", "web server recon"
    ],
    "run_full_scan": [
        "full scan", "complete recon", "enumerate everything", "full recon",
        "end-to-end scan", "scan and enrich", "pipeline scan", "fingerprinting",
        "cve lookup", "run all scans", "multi-tool scan", "automated recon",
        "network profiling", "threat surface mapping"
    ]
}


def match_tool(prompt: str) -> str:
    prompt_lower = prompt.lower()
    words = set(prompt_lower.split())

    # 1. Direct tool name match (e.g., 'masscan' in prompt)
    for tool in TOOL_KEYWORDS:
        if tool in words or tool in prompt_lower:
            logging.info(f"[TOOL MATCH] Direct tool name match: {tool}")
            return tool

    # 2. Keyword match (only if keyword is a whole word in the prompt)
    for tool, keywords in TOOL_KEYWORDS.items():
        for kw in keywords:
            if kw in words or f' {kw} ' in f' {prompt_lower} ':
                logging.info(f"[TOOL MATCH] Keyword match: {tool} for keyword '{kw}'")
                return tool

    # 3. No fuzzy match: only return None if no direct match
    return None
