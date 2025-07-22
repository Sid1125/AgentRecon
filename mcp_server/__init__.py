"""
AgentRecon MCP Server Package
Model Context Protocol server for workflow orchestration and task management
"""

from .workflow_manager import workflow_manager, WorkflowManager
from .config import PREDEFINED_WORKFLOWS, validate_target

__version__ = "1.0.0"
__all__ = ["workflow_manager", "WorkflowManager", "PREDEFINED_WORKFLOWS", "validate_target"]
