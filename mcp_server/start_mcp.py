#!/usr/bin/env python3
"""
MCP Server Startup Script for AgentRecon
"""

import logging
import logging.config
from pathlib import Path
import sys

# Add the parent directory to the path so we can import AgentRecon modules
sys.path.append(str(Path(__file__).parent.parent))

from mcp_server.config import LOGGING_CONFIG, SERVER_CONFIG
from mcp_server.workflow_manager import workflow_manager

def setup_logging():
    """Setup logging configuration"""
    logging.config.dictConfig(LOGGING_CONFIG)
    logger = logging.getLogger(__name__)
    logger.info("Logging configured successfully")
    return logger

def initialize_mcp():
    """Initialize MCP components"""
    logger = setup_logging()
    
    logger.info(f"Starting AgentRecon MCP Server v{SERVER_CONFIG['version']}")
    logger.info(f"Max concurrent tasks: {SERVER_CONFIG['max_concurrent_tasks']}")
    
    # Initialize workflow manager
    logger.info("Initializing workflow manager...")
    workflows = workflow_manager.get_available_workflows()
    logger.info(f"Loaded {len(workflows)} predefined workflows")
    
    # Log available workflows
    for name, config in workflows.items():
        logger.info(f"  - {name}: {config['description']}")
    
    logger.info("MCP Server initialization complete")
    return logger

def test_workflow_detection():
    """Test workflow detection functionality"""
    logger = logging.getLogger(__name__)
    
    test_prompts = [
        "run a full scan on example.com",
        "do a quick scan of 192.168.1.1", 
        "perform web scan on testsite.com",
        "scan example.com with nmap",
        "comprehensive scan of target.net"
    ]
    
    logger.info("Testing workflow detection:")
    for prompt in test_prompts:
        detected = workflow_manager.detect_workflow_intent(prompt)
        should_use = workflow_manager.should_use_workflow(prompt)
        logger.info(f"  '{prompt}' -> {detected} (use workflow: {should_use})")

if __name__ == "__main__":
    try:
        logger = initialize_mcp()
        
        # Run tests if requested
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            test_workflow_detection()
        
        logger.info("MCP Server ready for integration")
        
    except Exception as e:
        print(f"Failed to start MCP Server: {e}")
        sys.exit(1)
