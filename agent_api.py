from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
from typing import List
from langchain_agent.agent_runner import run_prompt, create_agent, match_tool, load_registered_tools
from langchain_agent.memory.history_manager import add_record
from mcp_server.workflow_manager import workflow_manager
import re
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

app = FastAPI()

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: list[Message]


def extract_target_from_prompt(prompt: str) -> str:
    """
    Extract target (domain/IP) from prompt with high reliability.
    Enhanced to properly handle subdomains like s.amizone.net
    """

    # Method 1: Enhanced domain patterns (more comprehensive)
    domain_patterns = [
        # Pattern 1: Full domain with subdomains (like s.amizone.net)
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b',
        # Pattern 2: Simple domain matching for multi-level domains
        r'\b([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})\b',
        # Pattern 3: Basic domain (two parts)
        r'\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b'
    ]

    # Try each pattern in order
    for pattern in domain_patterns:
        domains = re.findall(pattern, prompt)
        if domains:
            target = domains[-1]  # Take the last found domain
            return target

    # Method 2: Look for IP addresses
    ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    ips = re.findall(ip_pattern, prompt)
    if ips:
        target = ips[-1]
        return target

    # Method 3: Look for specific patterns after keywords
    keyword_patterns = [
        r'(?:scan|check|lookup|on|target)\s+([a-zA-Z0-9\-\.]+)',
        r'(?:against|from)\s+([a-zA-Z0-9\-\.]+)',
    ]

    for pattern in keyword_patterns:
        match = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            candidate = match.group(1)
            # Validate it's not a common word
            if candidate.lower() not in ['on', 'at', 'to', 'from', 'with', 'and', 'or', 'the', 'a', 'an']:
                return candidate

    # Method 4: Word-by-word analysis
    words = prompt.split()
    for word in reversed(words):
        clean_word = re.sub(r'[^\w\.\-]', '', word)
        if clean_word and '.' in clean_word:
            # Make sure it's not a common preposition
            if clean_word.lower() not in ['on', 'at', 'to', 'from', 'with']:
                return clean_word

    # Final fallback - but validate it's reasonable
    if words:
        last_word = re.sub(r'[^\w\.\-]', '', words[-1])
        if last_word.lower() not in ['on', 'at', 'to', 'from', 'with', 'and', 'or', 'the', 'a', 'an']:
            return last_word

    return ""


@app.post("/v1/chat/completions")
async def chat(request: ChatRequest):
    try:
        # Validate request structure
        if not request.messages or len(request.messages) == 0:
            raise HTTPException(status_code=422, detail="No messages provided")
        
        if not hasattr(request.messages[-1], 'content') or not request.messages[-1].content:
            raise HTTPException(status_code=422, detail="Message content is empty")
            
        prompt = request.messages[-1].content
        # Removed info print
        
    except AttributeError as e:
        print(f"[ERROR] Request validation failed: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid request format: {str(e)}")
    except Exception as e:
        print(f"[ERROR] Unexpected error in request handling: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    # Extract target using improved function
    target = extract_target_from_prompt(prompt)
    # Removed info print

    # Validate target
    if not target:
        error_msg = "Error: Could not determine target from the command. Please specify a valid domain or IP address."
        return {
            "id": "chatcmpl-001",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": error_msg
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": len(error_msg.split()),
                "total_tokens": len(error_msg.split()) + 1
            },
            "model": request.model
        }

    # Double-check target is not a common word
    if target.lower() in ['on', 'at', 'to', 'from', 'with', 'and', 'or', 'the', 'a', 'an']:
        error_msg = f"Error: Invalid target '{target}'. Please check your command syntax."
        return {
            "id": "chatcmpl-001",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": error_msg
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": len(error_msg.split()),
                "total_tokens": len(error_msg.split()) + 1
            },
            "model": request.model
        }

    # Use the centralized run_prompt function which handles workflows and tools
    try:
        response = run_prompt(prompt)
    except Exception as e:
        print(f"[ERROR] Tool execution failed: {e}")
        error_response = f"Error executing security scan: {str(e)}"
        return {
            "id": "chatcmpl-001",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": error_response
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": len(error_response.split()),
                "total_tokens": len(error_response.split()) + 1
            },
            "model": request.model
        }

    return {
        "id": "chatcmpl-001",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": len(response.split()),
            "total_tokens": len(response.split()) + 1
        },
        "model": request.model
    }


# Required for Open WebUI compatibility
@app.get("/v1/models")
async def models():
    return {
        "object": "list",
        "data": [
            {
                "id": "mistral-nemo:latest",
                "object": "model",
                "owned_by": "agentrecon"
            }
        ]
    }


@app.get("/v1/api/tags")
async def tags():
    return []


@app.get("/v1/api/ps")
async def ps():
    return []


@app.get("/v1/api/version")
async def version():
    return {"version": "0.1.0-agentrecon"}