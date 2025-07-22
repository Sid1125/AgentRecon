"""
Workflow tools for LangChain integration
Provides LangChain-compatible tools for workflow management
"""

import json
from langchain_core.tools import tool
from .workflow_manager import workflow_manager

@tool
def run_workflow(target: str, workflow_type: str = "quick_scan") -> str:
    """
    Execute a predefined scanning workflow on a target.
    
    Args:
        target: IP address or hostname to scan
        workflow_type: Type of workflow to execute:
            - quick_scan: Fast port discovery and basic service enumeration
            - web_scan: Comprehensive web application security assessment  
            - full_recon: Complete reconnaissance including all available tools
            - network_discovery: Network and host discovery focused scan
            - vulnerability_assessment: Comprehensive vulnerability identification
            - ssl_audit: Focused SSL/TLS security assessment
    
    Returns:
        Formatted workflow execution results
    """
    return workflow_manager.execute_workflow_sync(target, workflow_type)

@tool  
def list_workflows() -> str:
    """
    List all available workflow types and their descriptions.
    
    Returns:
        JSON string with available workflow information
    """
    workflows = workflow_manager.get_available_workflows()
    
    formatted_output = "# Available Workflows\n\n"
    for workflow_type, info in workflows.items():
        formatted_output += f"## {info['name']} (`{workflow_type}`)\n"
        formatted_output += f"**Description**: {info['description']}\n"
        formatted_output += f"**Tools**: {', '.join(info['tools'])}\n"
        formatted_output += f"**Estimated Time**: {info['estimated_time']}\n\n"
    
    return formatted_output

@tool
def get_workflow_status(workflow_id: str) -> str:
    """
    Get the status of a running workflow.
    
    Args:
        workflow_id: The workflow ID to check
        
    Returns:
        JSON string with workflow status information
    """
    status = workflow_manager.get_workflow_status(workflow_id)
    return json.dumps(status, indent=2)

@tool
def list_active_workflows() -> str:
    """
    List all currently active workflows.
    
    Returns:
        JSON string with active workflow information
    """
    active = workflow_manager.list_active_workflows()
    
    if not active:
        return "No active workflows currently running."
    
    formatted_output = "# Active Workflows\n\n"
    for workflow in active:
        formatted_output += f"## Workflow {workflow['id']}\n"
        formatted_output += f"**Type**: {workflow['type']}\n"
        formatted_output += f"**Target**: {workflow['target']}\n"
        formatted_output += f"**Status**: {workflow['status']}\n"
        formatted_output += f"**Progress**: {workflow['progress']}\n\n"
    
    return formatted_output
