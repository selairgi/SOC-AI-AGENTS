"""
Agent discovery and monitoring system for AI agent environments.
"""

import asyncio
import json
import os
import time
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

from .models import AgentInfo, AgentType, LogEntry
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from security.security_rules import SecurityRulesEngine


class AgentMonitor:
    """Monitors and discovers AI agents in the environment."""
    
    def __init__(self, security_rules_engine: SecurityRulesEngine):
        self.security_rules_engine = security_rules_engine
        self.discovered_agents: Dict[str, AgentInfo] = {}
        self.agent_logs: Dict[str, List[LogEntry]] = {}
        self.logger = logging.getLogger("AgentMonitor")
        self._stopped = False
        
    async def discover_agents(self, scan_paths: List[str] = None) -> Dict[str, AgentInfo]:
        """Discover AI agents in the specified paths."""
        if scan_paths is None:
            scan_paths = [".", "..", "../.."]  # Default scan paths
            
        self.logger.info(f"Starting agent discovery in paths: {scan_paths}")
        
        for path in scan_paths:
            await self._scan_directory(path)
            
        self.logger.info(f"Discovered {len(self.discovered_agents)} agents")
        return self.discovered_agents
    
    async def _scan_directory(self, directory: str):
        """Scan a directory for AI agent files."""
        try:
            path = Path(directory)
            if not path.exists():
                return
                
            # Look for common AI agent patterns
            patterns = [
                "*agent*.py",
                "*ai*.py", 
                "*llm*.py",
                "*gpt*.py",
                "*claude*.py",
                "*model*.py",
                "main.py",
                "app.py",
                "server.py"
            ]
            
            for pattern in patterns:
                for file_path in path.rglob(pattern):
                    if file_path.is_file() and file_path.suffix == ".py":
                        await self._analyze_agent_file(file_path)
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
    
    async def _analyze_agent_file(self, file_path: Path):
        """Analyze a Python file to determine if it's an AI agent."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple heuristics to identify AI agents
            ai_indicators = [
                "openai", "anthropic", "llm", "gpt", "claude", "model",
                "chat", "completion", "prompt", "agent", "assistant",
                "langchain", "llama", "huggingface", "transformers"
            ]
            
            content_lower = content.lower()
            ai_score = sum(1 for indicator in ai_indicators if indicator in content_lower)
            
            if ai_score >= 2:  # Threshold for considering it an AI agent
                agent_info = self._extract_agent_info(file_path, content)
                if agent_info:
                    self.discovered_agents[agent_info.agent_id] = agent_info
                    self.logger.info(f"Discovered agent: {agent_info.name} ({agent_info.agent_id})")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
    
    def _extract_agent_info(self, file_path: Path, content: str) -> Optional[AgentInfo]:
        """Extract agent information from file content."""
        try:
            # Extract basic info
            agent_id = f"{file_path.stem}_{file_path.parent.name}"
            name = file_path.stem.replace("_", " ").title()
            
            # Determine agent type based on content and path
            agent_type = self._determine_agent_type(content, file_path)
            
            # Extract endpoints (look for Flask, FastAPI, etc.)
            endpoints = self._extract_endpoints(content)
            
            # Extract capabilities
            capabilities = self._extract_capabilities(content)
            
            # Determine security level
            security_level = self._determine_security_level(content, agent_type)
            
            return AgentInfo(
                agent_id=agent_id,
                agent_type=agent_type,
                name=name,
                description=f"AI agent discovered in {file_path}",
                endpoints=endpoints,
                capabilities=capabilities,
                security_level=security_level,
                metadata={
                    "file_path": str(file_path),
                    "discovery_time": time.time(),
                    "content_length": len(content)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting agent info from {file_path}: {e}")
            return None
    
    def _determine_agent_type(self, content: str, file_path: Path) -> AgentType:
        """Determine the type of AI agent based on content and path."""
        content_lower = content.lower()
        path_lower = str(file_path).lower()
        
        # Medical agents
        if any(keyword in content_lower or keyword in path_lower 
               for keyword in ["medical", "doctor", "health", "diagnosis", "patient", "clinical"]):
            return AgentType.MEDICAL
            
        # Financial agents
        elif any(keyword in content_lower or keyword in path_lower 
                for keyword in ["financial", "bank", "finance", "trading", "investment", "payment"]):
            return AgentType.FINANCIAL
            
        # Customer service agents
        elif any(keyword in content_lower or keyword in path_lower 
                for keyword in ["customer", "support", "service", "help", "chatbot"]):
            return AgentType.CUSTOMER_SERVICE
            
        # Code assistant agents
        elif any(keyword in content_lower or keyword in path_lower 
                for keyword in ["code", "programming", "developer", "coding", "debug", "syntax"]):
            return AgentType.CODE_ASSISTANT
            
        # Research agents
        elif any(keyword in content_lower or keyword in path_lower 
                for keyword in ["research", "analysis", "study", "investigation"]):
            return AgentType.RESEARCH
            
        else:
            return AgentType.GENERAL
    
    def _extract_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from the content."""
        endpoints = []
        
        # Look for Flask routes
        import re
        flask_routes = re.findall(r'@app\.route\(["\']([^"\']+)["\']', content)
        endpoints.extend(flask_routes)
        
        # Look for FastAPI routes
        fastapi_routes = re.findall(r'@app\.(get|post|put|delete)\(["\']([^"\']+)["\']', content)
        endpoints.extend([route[1] for route in fastapi_routes])
        
        return endpoints
    
    def _extract_capabilities(self, content: str) -> List[str]:
        """Extract agent capabilities from content."""
        capabilities = []
        content_lower = content.lower()
        
        capability_mapping = {
            "text generation": ["generate", "completion", "text"],
            "conversation": ["chat", "conversation", "dialogue"],
            "code analysis": ["code", "syntax", "debug", "analyze"],
            "data processing": ["process", "analyze", "data"],
            "file handling": ["file", "upload", "download"],
            "api integration": ["api", "request", "http"],
            "database access": ["database", "db", "sql", "query"],
            "image processing": ["image", "vision", "ocr"],
            "translation": ["translate", "language"],
            "summarization": ["summarize", "summary"]
        }
        
        for capability, keywords in capability_mapping.items():
            if any(keyword in content_lower for keyword in keywords):
                capabilities.append(capability)
        
        return capabilities if capabilities else ["general purpose"]
    
    def _determine_security_level(self, content: str, agent_type: AgentType) -> str:
        """Determine the security level of an agent."""
        content_lower = content.lower()
        
        # High-risk indicators
        high_risk_keywords = [
            "admin", "root", "sudo", "system", "shell", "exec", "eval",
            "database", "sql", "delete", "drop", "update", "insert",
            "api_key", "secret", "password", "token", "credential"
        ]
        
        # Critical data types
        critical_data_keywords = [
            "patient", "medical", "financial", "credit", "ssn", "social security",
            "bank account", "payment", "transaction"
        ]
        
        risk_score = 0
        risk_score += sum(1 for keyword in high_risk_keywords if keyword in content_lower)
        risk_score += sum(2 for keyword in critical_data_keywords if keyword in content_lower)
        
        # Agent type risk
        if agent_type in [AgentType.MEDICAL, AgentType.FINANCIAL]:
            risk_score += 2
        elif agent_type == AgentType.CODE_ASSISTANT:
            risk_score += 1
        
        if risk_score >= 5:
            return "critical"
        elif risk_score >= 3:
            return "high"
        elif risk_score >= 1:
            return "medium"
        else:
            return "low"
    
    async def monitor_agent_activity(self, agent_id: str, log_source_func):
        """Monitor activity for a specific agent."""
        self.logger.info(f"Starting monitoring for agent: {agent_id}")
        
        if agent_id not in self.agent_logs:
            self.agent_logs[agent_id] = []
        
        try:
            async for log_entry in log_source_func():
                if self._stopped:
                    break
                    
                # Add agent context to log
                log_entry.agent_id = agent_id
                self.agent_logs[agent_id].append(log_entry)
                
                # Keep only recent logs (last 1000 entries)
                if len(self.agent_logs[agent_id]) > 1000:
                    self.agent_logs[agent_id] = self.agent_logs[agent_id][-1000:]
                
        except Exception as e:
            self.logger.error(f"Error monitoring agent {agent_id}: {e}")
    
    def get_agent_logs(self, agent_id: str, limit: int = 100) -> List[LogEntry]:
        """Get recent logs for a specific agent."""
        if agent_id not in self.agent_logs:
            return []
        return self.agent_logs[agent_id][-limit:]
    
    def get_all_agents(self) -> Dict[str, AgentInfo]:
        """Get all discovered agents."""
        return self.discovered_agents.copy()
    
    def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """Get information about a specific agent."""
        return self.discovered_agents.get(agent_id)
    
    def stop(self):
        """Stop the agent monitor."""
        self._stopped = True
        self.logger.info("Agent monitor stopped")

