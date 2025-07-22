"""
WorkflowManager for AgentRecon MCP Integration
Handles workflow orchestration within the existing agent_runner system
"""

import asyncio
import json
import uuid
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
import sys

from .config import PREDEFINED_WORKFLOWS, validate_target, SECURITY_CONFIG

logger = logging.getLogger(__name__)

class WorkflowManager:
    """Manages scanning workflows and integrates with existing agent system"""
    
    def __init__(self):
        self.active_workflows: Dict[str, Dict] = {}
        self.workflow_history: List[Dict] = []
        self.rate_limiter: Dict[str, List[float]] = {}  # target -> list of timestamps
        
    def detect_workflow_intent(self, prompt: str) -> Optional[str]:
        """
        Detect if the prompt is asking for a workflow rather than a single tool
        """
        workflow_keywords = {
            "full scan": "full_recon",
            "complete scan": "full_recon", 
            "full recon": "full_recon",
            "comprehensive scan": "full_recon",
            "quick scan": "quick_scan",
            "fast scan": "quick_scan",
            "web scan": "web_scan",
            "web app scan": "web_scan",
            "website scan": "web_scan",
            "network discovery": "network_discovery",
            "network scan": "network_discovery",
            "vulnerability assessment": "vulnerability_assessment",
            "vuln scan": "vulnerability_assessment",
            "ssl audit": "ssl_audit",
            "ssl scan": "ssl_audit",
            "tls scan": "ssl_audit"
        }
        
        prompt_lower = prompt.lower()
        
        # Look for workflow keywords
        for keyword, workflow_type in workflow_keywords.items():
            if keyword in prompt_lower:
                return workflow_type
        
        # Check for multiple tool mentions (suggests workflow)
        tool_mentions = 0
        tool_keywords = ["nmap", "masscan", "nikto", "gobuster", "sslyze", "rustscan"]
        for tool in tool_keywords:
            if tool in prompt_lower:
                tool_mentions += 1
        
        if tool_mentions > 1:
            return "full_recon"  # Default to full recon for multiple tools
            
        return None
    
    def should_use_workflow(self, prompt: str) -> bool:
        """Determine if a workflow should be used instead of individual tool"""
        workflow_indicators = [
            "run all", "complete", "comprehensive", "full", "everything",
            "workflow", "pipeline", "end-to-end", "thorough"
        ]
        
        prompt_lower = prompt.lower()
        return any(indicator in prompt_lower for indicator in workflow_indicators)
    
    def validate_workflow_request(self, target: str, workflow_type: str) -> Dict[str, Any]:
        """Validate if workflow can be executed on target"""
        
        # Validate target
        target_validation = validate_target(target)
        if not target_validation["allowed"]:
            return {
                "allowed": False,
                "reason": target_validation["reason"]
            }
        
        # Check rate limiting
        if SECURITY_CONFIG["rate_limiting"]["enabled"]:
            current_time = time.time()
            hour_ago = current_time - 3600
            
            # Clean old entries
            if target in self.rate_limiter:
                self.rate_limiter[target] = [
                    t for t in self.rate_limiter[target] if t > hour_ago
                ]
            else:
                self.rate_limiter[target] = []
            
            # Check limits
            scans_this_hour = len(self.rate_limiter[target])
            max_scans = SECURITY_CONFIG["rate_limiting"]["max_scans_per_target_per_hour"]
            
            if scans_this_hour >= max_scans:
                return {
                    "allowed": False,
                    "reason": f"Rate limit exceeded: {scans_this_hour}/{max_scans} scans per hour for {target}"
                }
        
        # Check if workflow exists
        if workflow_type not in PREDEFINED_WORKFLOWS:
            return {
                "allowed": False,
                "reason": f"Unknown workflow type: {workflow_type}"
            }
        
        return {"allowed": True, "reason": "Validation passed"}
    
    def execute_workflow_sync(self, target: str, workflow_type: str = "quick_scan") -> str:
        """
        Execute workflow synchronously (for integration with existing sync agent_runner)
        """
        try:
            # Validate request
            validation = self.validate_workflow_request(target, workflow_type)
            if not validation["allowed"]:
                return f"Workflow blocked: {validation['reason']}"
            
            # Get workflow config
            workflow_config = PREDEFINED_WORKFLOWS.get(workflow_type)
            if not workflow_config:
                return f"Unknown workflow type: {workflow_type}"
            
            # Create workflow instance
            workflow_id = str(uuid.uuid4())[:8]
            workflow_instance = {
                "id": workflow_id,
                "type": workflow_type,
                "target": target,
                "status": "running",
                "started_at": datetime.now(),
                "tools": workflow_config["tools"],
                "results": {},
                "current_tool": 0
            }
            
            self.active_workflows[workflow_id] = workflow_instance
            
            # Update rate limiter
            if SECURITY_CONFIG["rate_limiting"]["enabled"]:
                if target not in self.rate_limiter:
                    self.rate_limiter[target] = []
                self.rate_limiter[target].append(time.time())
            
            logger.info(f"Starting workflow {workflow_id} ({workflow_type}) for {target}")
            
            # Import here to avoid circular imports
            from langchain_agent.agent_runner import load_registered_tools
            
            # Load available tools
            available_tools = {t.name: t for t in load_registered_tools()}
            
            # Execute workflow tools
            workflow_results = []
            tool_filepaths = {}
            for i, tool_name in enumerate(workflow_config["tools"]):
                workflow_instance["current_tool"] = i

                logger.info(f"Executing {tool_name} in workflow {workflow_id}")
                try:
                    tool_params = {"target": target}
                    if tool_name == "nmap":
                        tool_params.update({"scan_type": "default", "timing": "4"})
                    elif tool_name == "masscan":
                        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
                        tool_params["ports"] = common_ports
                    elif tool_name == "rustscan":
                        tool_params["ports"] = "1-1000"
                    tool_params = {k: v for k, v in tool_params.items() if v is not None}
                    result = available_tools[tool_name].invoke(tool_params)
                    # If the tool returns a dict with 'output' and 'file', store the file path for run_full_scan
                    if isinstance(result, dict) and "file" in result:
                        tool_filepaths[tool_name] = result["file"]
                        tool_output = result["output"]
                    else:
                        tool_output = result
                    # If this is run_full_scan, pass file paths for all previous tools
                    if tool_name == "run_full_scan":
                        scan_args = {"target": target}
                        # Map tool wrapper names to run_full_scan arg names
                        for k in ["nmap", "masscan", "rustscan", "nikto", "sslyze", "gobuster"]:
                            v = tool_filepaths.get(f"run_{k}")
                            if isinstance(v, str) and v:
                                scan_args[k] = v
                        tool_output = available_tools[tool_name].invoke(scan_args)
                    # Improve error messaging for Nikto and sslyze
                    if tool_name == "nikto" and "not supported on Windows" in tool_output:
                        status = "skipped"
                    elif tool_name == "sslyze" and ("connection refused" in tool_output.lower() or "timeout" in tool_output.lower()):
                        status = "error"
                        tool_output = "No SSL/TLS service detected on port 443."
                    else:
                        status = "success"
                    workflow_instance["results"][tool_name] = {
                        "status": status,
                        "output": tool_output,
                        "timestamp": datetime.now().isoformat()
                    }
                    workflow_results.append({
                        "tool": tool_name,
                        "status": status,
                        "output_preview": tool_output[:200] + "..." if isinstance(tool_output, str) and len(tool_output) > 200 else tool_output
                    })
                except Exception as e:
                    error_msg = f"Error executing {tool_name}: {str(e)}"
                    logger.error(error_msg)
                    workflow_instance["results"][tool_name] = {
                        "status": "error",
                        "error": error_msg,
                        "timestamp": datetime.now().isoformat()
                    }
                    workflow_results.append({
                        "tool": tool_name,
                        "status": "error",
                        "error": error_msg
                    })
            
            # Mark workflow as completed
            workflow_instance["status"] = "completed"
            workflow_instance["completed_at"] = datetime.now()
            
            # Add to history
            self.workflow_history.append(workflow_instance.copy())
            
            # Format results
            successful_tools = len([r for r in workflow_results if r["status"] == "success"])
            total_tools = len(workflow_results)
            
            formatted_output = f"""# Workflow Results: {workflow_config['name']}

**Target**: `{target}`
**Workflow ID**: `{workflow_id}`
**Status**: ✅ Completed
**Tools Executed**: {len([r for r in workflow_results if r['status'] == 'success'])}/{len(workflow_results)} successful

## Tool Results:
"""
            
            for result in workflow_results:
                if result["status"] == "success":
                    status_icon = "✅"
                elif result["status"] == "skipped":
                    status_icon = "⏭️"
                else:
                    status_icon = "❌"
                formatted_output += f"\n### {status_icon} {result['tool']}\n"
                
                if result["status"] == "success":
                    formatted_output += f"```\n{result['output_preview']}\n```\n"
                elif result["status"] == "skipped":
                    formatted_output += f"**Skipped**: {result.get('error', 'Skipped by workflow logic')}\n"
                else:
                    formatted_output += f"**Error**: {result.get('error', result.get('output_preview', 'Unknown error'))}\n"
            
            formatted_output += f"\n---\n*Workflow completed at {datetime.now().strftime('%H:%M:%S')}*"
            
            logger.info(f"Completed workflow {workflow_id}")
            return formatted_output
            
        except Exception as e:
            error_msg = f"Workflow execution failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get status of a running workflow"""
        if workflow_id not in self.active_workflows:
            return {"error": f"Workflow {workflow_id} not found"}
        
        workflow = self.active_workflows[workflow_id]
        return {
            "id": workflow["id"],
            "type": workflow["type"],
            "target": workflow["target"],
            "status": workflow["status"],
            "progress": f"{workflow.get('current_tool', 0)}/{len(workflow['tools'])}",
            "tools_completed": len([r for r in workflow["results"].values() if r.get("status") == "completed"]),
            "total_tools": len(workflow["tools"])
        }
    
    def list_active_workflows(self) -> List[Dict[str, Any]]:
        """List all active workflows"""
        return [
            self.get_workflow_status(wf_id) 
            for wf_id in self.active_workflows.keys()
        ]
    
    def get_available_workflows(self) -> Dict[str, Any]:
        """Get list of available workflow types"""
        return {
            name: {
                "name": config["name"],
                "description": config["description"],
                "tools": config["tools"],
                "estimated_time": f"{config.get('timeout', 300)}s"
            }
            for name, config in PREDEFINED_WORKFLOWS.items()
        }

# Global workflow manager instance
workflow_manager = WorkflowManager()
