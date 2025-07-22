#!/usr/bin/env python3
"""
AgentRecon MCP Server
Orchestrates security scanning workflows and manages external tool integration
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Note: MCP Protocol imports removed for simplified implementation
# This is a standalone workflow orchestration system

# AgentRecon imports
from langchain_agent.agent_runner import load_registered_tools
from langchain_agent.memory.history_manager import add_record, get_last_scan

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScanTask:
    id: str
    target: str
    tool_name: str
    parameters: Dict[str, Any]
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self):
        return {
            **asdict(self),
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status.value
        }

# This file is kept for reference but not used in the simplified implementation
# The WorkflowManager in workflow_manager.py handles all functionality

class AgentReconMCP:
    """Legacy MCP server class - functionality moved to WorkflowManager"""
    def __init__(self):
        print("Note: This class is deprecated. Use WorkflowManager instead.")
    
    def _load_tools(self):
        """Load registered security tools"""
        try:
            tools = load_registered_tools()
            for tool in tools:
                self.tool_registry[tool.name] = tool
            logger.info(f"Loaded {len(self.tool_registry)} security tools")
        except Exception as e:
            logger.error(f"Failed to load tools: {e}")
    
    def _register_mcp_tools(self):
        """Register MCP protocol tools"""
        
        @self.server.tool("execute_scan")
        async def execute_scan(target: str, tool_name: str, parameters: Dict[str, Any] = None) -> str:
            """Execute a security scan on the target using specified tool"""
            return await self._execute_scan(target, tool_name, parameters or {})
        
        @self.server.tool("get_scan_status")
        async def get_scan_status(task_id: str) -> str:
            """Get the status of a running scan task"""
            return await self._get_scan_status(task_id)
        
        @self.server.tool("list_active_scans")
        async def list_active_scans() -> str:
            """List all active/pending scan tasks"""
            return await self._list_active_scans()
        
        @self.server.tool("cancel_scan")
        async def cancel_scan(task_id: str) -> str:
            """Cancel a running scan task"""
            return await self._cancel_scan(task_id)
        
        @self.server.tool("get_available_tools")
        async def get_available_tools() -> str:
            """Get list of available security tools"""
            return await self._get_available_tools()
        
        @self.server.tool("run_workflow")
        async def run_workflow(target: str, workflow_type: str = "full_recon") -> str:
            """Execute a predefined scanning workflow"""
            return await self._run_workflow(target, workflow_type)
        
        @self.server.tool("get_target_history")
        async def get_target_history(target: str) -> str:
            """Get historical scan data for a target"""
            return await self._get_target_history(target)
    
    async def _execute_scan(self, target: str, tool_name: str, parameters: Dict[str, Any]) -> str:
        """Execute a single security scan"""
        
        # Validate tool exists
        if tool_name not in self.tool_registry:
            return json.dumps({
                "error": f"Tool '{tool_name}' not found",
                "available_tools": list(self.tool_registry.keys())
            })
        
        # Check concurrent task limit
        if len(self.running_tasks) >= self.max_concurrent_tasks:
            return json.dumps({
                "error": "Maximum concurrent tasks reached",
                "max_concurrent": self.max_concurrent_tasks,
                "running_tasks": len(self.running_tasks)
            })
        
        # Create task
        task_id = str(uuid.uuid4())
        task = ScanTask(
            id=task_id,
            target=target,
            tool_name=tool_name,
            parameters=parameters,
            status=TaskStatus.PENDING,
            created_at=datetime.now()
        )
        
        self.tasks[task_id] = task
        
        # Execute scan asynchronously
        asyncio.create_task(self._run_scan_task(task))
        
        return json.dumps({
            "task_id": task_id,
            "status": "pending",
            "message": f"Scan '{tool_name}' queued for target '{target}'"
        })
    
    async def _run_scan_task(self, task: ScanTask):
        """Execute the actual scan task"""
        try:
            self.running_tasks.add(task.id)
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            logger.info(f"Starting scan {task.id}: {task.tool_name} -> {task.target}")
            
            # Get the tool and execute it
            tool = self.tool_registry[task.tool_name]
            
            # Prepare parameters - merge with defaults
            scan_params = {
                "target": task.target,
                **task.parameters
            }
            
            # Execute the tool
            result = await asyncio.to_thread(tool.invoke, scan_params)
            
            # Mark as completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.result = result
            
            # Save to history
            add_record(
                prompt=f"MCP scan: {task.tool_name}",
                tool=task.tool_name,
                target=task.target,
                output=result
            )
            
            logger.info(f"Completed scan {task.id}")
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            task.error = str(e)
            logger.error(f"Scan {task.id} failed: {e}")
            
        finally:
            self.running_tasks.discard(task.id)
    
    async def _get_scan_status(self, task_id: str) -> str:
        """Get status of a specific task"""
        if task_id not in self.tasks:
            return json.dumps({"error": f"Task {task_id} not found"})
        
        task = self.tasks[task_id]
        return json.dumps(task.to_dict())
    
    async def _list_active_scans(self) -> str:
        """List all active scans"""
        active_tasks = [
            task.to_dict() for task in self.tasks.values()
            if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]
        ]
        
        return json.dumps({
            "active_tasks": active_tasks,
            "total_active": len(active_tasks),
            "running": len(self.running_tasks)
        })
    
    async def _cancel_scan(self, task_id: str) -> str:
        """Cancel a scan task"""
        if task_id not in self.tasks:
            return json.dumps({"error": f"Task {task_id} not found"})
        
        task = self.tasks[task_id]
        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            return json.dumps({"error": f"Task {task_id} cannot be cancelled (status: {task.status.value})"})
        
        task.status = TaskStatus.CANCELLED
        task.completed_at = datetime.now()
        self.running_tasks.discard(task_id)
        
        return json.dumps({
            "message": f"Task {task_id} cancelled",
            "task_id": task_id
        })
    
    async def _get_available_tools(self) -> str:
        """Get list of available security tools"""
        tools_info = []
        for name, tool in self.tool_registry.items():
            tools_info.append({
                "name": name,
                "description": getattr(tool, 'description', 'No description available')
            })
        
        return json.dumps({
            "available_tools": tools_info,
            "total_tools": len(tools_info)
        })
    
    async def _run_workflow(self, target: str, workflow_type: str) -> str:
        """Execute a predefined scanning workflow"""
        
        workflows = {
            "quick_scan": ["run_rustscan", "run_nmap"],
            "web_scan": ["run_nmap", "run_nikto", "run_gobuster", "run_sslyze"],
            "full_recon": ["run_masscan", "run_nmap", "run_nikto", "run_gobuster", "run_sslyze"],
            "network_discovery": ["run_masscan", "run_nmap"],
            "vulnerability_assessment": ["run_nmap", "run_nikto", "run_full_scan"]
        }
        
        if workflow_type not in workflows:
            return json.dumps({
                "error": f"Unknown workflow type '{workflow_type}'",
                "available_workflows": list(workflows.keys())
            })
        
        workflow_tools = workflows[workflow_type]
        workflow_id = str(uuid.uuid4())
        task_ids = []
        
        logger.info(f"Starting workflow '{workflow_type}' for target '{target}'")
        
        # Execute tools in sequence for now (can be made parallel later)
        for tool_name in workflow_tools:
            if tool_name in self.tool_registry:
                result = await self._execute_scan(target, tool_name, {})
                result_data = json.loads(result)
                if "task_id" in result_data:
                    task_ids.append(result_data["task_id"])
            else:
                logger.warning(f"Tool {tool_name} not available in workflow")
        
        return json.dumps({
            "workflow_id": workflow_id,
            "workflow_type": workflow_type,
            "target": target,
            "task_ids": task_ids,
            "total_tasks": len(task_ids)
        })
    
    async def _get_target_history(self, target: str) -> str:
        """Get historical scan data for a target"""
        try:
            last_scan = get_last_scan(target)
            if last_scan:
                return json.dumps({
                    "target": target,
                    "has_history": True,
                    "last_scan": last_scan
                })
            else:
                return json.dumps({
                    "target": target,
                    "has_history": False,
                    "message": "No previous scans found for this target"
                })
        except Exception as e:
            return json.dumps({
                "error": f"Failed to retrieve history: {str(e)}",
                "target": target
            })

async def main():
    """Main entry point for the MCP server"""
    mcp = AgentReconMCP()
    
    # Run the server
    async with mcp.server.stdio_transport() as (read_stream, write_stream):
        logger.info("AgentRecon MCP Server started")
        await mcp.server.run(read_stream, write_stream, mcp.server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
