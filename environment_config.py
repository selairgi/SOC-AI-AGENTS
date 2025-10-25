"""
Configuration system for different AI agent environments.
"""

import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

from models import AgentType, SecurityRule, ThreatType


class EnvironmentConfig:
    """Configuration manager for different AI agent environments."""
    
    def __init__(self, config_file: str = "soc_config.json"):
        self.config_file = config_file
        self.config = self._load_default_config()
        self._load_config_file()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration for SOC system."""
        return {
            "environment": {
                "name": "default",
                "description": "Default AI agent environment",
                "scan_paths": [".", "..", "../.."],
                "monitoring_interval": 1.0,
                "log_retention_days": 30
            },
            "agent_discovery": {
                "enabled": True,
                "auto_scan": True,
                "scan_interval": 300,  # 5 minutes
                "file_patterns": [
                    "*agent*.py",
                    "*ai*.py",
                    "*llm*.py",
                    "*gpt*.py",
                    "*claude*.py",
                    "*model*.py",
                    "main.py",
                    "app.py",
                    "server.py"
                ],
                "exclude_patterns": [
                    "__pycache__",
                    ".git",
                    "node_modules",
                    "venv",
                    ".env"
                ]
            },
            "security_rules": {
                "enabled_rules": [
                    "PROMPT_INJ_001",
                    "PROMPT_INJ_002", 
                    "DATA_EXF_001",
                    "DATA_EXF_002",
                    "SYS_MAN_001",
                    "SYS_MAN_002",
                    "MED_001",
                    "FIN_001",
                    "RATE_001",
                    "MAL_INP_001"
                ],
                "custom_rules": []
            },
            "monitoring": {
                "log_levels": ["INFO", "WARNING", "ERROR"],
                "alert_thresholds": {
                    "high_severity": 1,
                    "medium_severity": 5,
                    "low_severity": 10
                },
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_minute": 100,
                    "burst_limit": 200
                }
            },
            "remediation": {
                "auto_remediate": False,
                "require_approval": True,
                "approval_timeout": 300,  # 5 minutes
                "escalation_levels": [
                    "security_team",
                    "security_manager", 
                    "ciso"
                ]
            },
            "integrations": {
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channels": ["#security-alerts"]
                },
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "recipients": []
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "headers": {}
                }
            }
        }
    
    def _load_config_file(self):
        """Load configuration from file if it exists."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self._merge_config(file_config)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
    
    def _merge_config(self, file_config: Dict[str, Any]):
        """Merge file configuration with default config."""
        def deep_merge(default: Dict, override: Dict):
            for key, value in override.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    deep_merge(default[key], value)
                else:
                    default[key] = value
        
        deep_merge(self.config, file_config)
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_environment_config(self) -> Dict[str, Any]:
        """Get environment configuration."""
        return self.config.get("environment", {})
    
    def get_scan_paths(self) -> List[str]:
        """Get scan paths for agent discovery."""
        return self.config.get("environment", {}).get("scan_paths", [".", "..", "../.."])
    
    def get_agent_discovery_config(self) -> Dict[str, Any]:
        """Get agent discovery configuration."""
        return self.config.get("agent_discovery", {})
    
    def get_security_rules_config(self) -> Dict[str, Any]:
        """Get security rules configuration."""
        return self.config.get("security_rules", {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return self.config.get("monitoring", {})
    
    def get_remediation_config(self) -> Dict[str, Any]:
        """Get remediation configuration."""
        return self.config.get("remediation", {})
    
    def get_integrations_config(self) -> Dict[str, Any]:
        """Get integrations configuration."""
        return self.config.get("integrations", {})
    
    def set_environment_name(self, name: str):
        """Set the environment name."""
        if "environment" not in self.config:
            self.config["environment"] = {}
        self.config["environment"]["name"] = name
    
    def add_scan_path(self, path: str):
        """Add a scan path for agent discovery."""
        if "environment" not in self.config:
            self.config["environment"] = {}
        if "scan_paths" not in self.config["environment"]:
            self.config["environment"]["scan_paths"] = []
        
        if path not in self.config["environment"]["scan_paths"]:
            self.config["environment"]["scan_paths"].append(path)
    
    def remove_scan_path(self, path: str):
        """Remove a scan path."""
        if "environment" in self.config and "scan_paths" in self.config["environment"]:
            self.config["environment"]["scan_paths"] = [
                p for p in self.config["environment"]["scan_paths"] if p != path
            ]
    
    def enable_rule(self, rule_id: str):
        """Enable a security rule."""
        if "security_rules" not in self.config:
            self.config["security_rules"] = {}
        if "enabled_rules" not in self.config["security_rules"]:
            self.config["security_rules"]["enabled_rules"] = []
        
        if rule_id not in self.config["security_rules"]["enabled_rules"]:
            self.config["security_rules"]["enabled_rules"].append(rule_id)
    
    def disable_rule(self, rule_id: str):
        """Disable a security rule."""
        if "security_rules" in self.config and "enabled_rules" in self.config["security_rules"]:
            self.config["security_rules"]["enabled_rules"] = [
                r for r in self.config["security_rules"]["enabled_rules"] if r != rule_id
            ]
    
    def add_custom_rule(self, rule: SecurityRule):
        """Add a custom security rule."""
        if "security_rules" not in self.config:
            self.config["security_rules"] = {}
        if "custom_rules" not in self.config["security_rules"]:
            self.config["security_rules"]["custom_rules"] = []
        
        rule_dict = {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "threat_type": rule.threat_type.value,
            "severity": rule.severity,
            "patterns": rule.patterns,
            "agent_types": [at.value for at in rule.agent_types],
            "enabled": rule.enabled,
            "metadata": rule.metadata
        }
        
        self.config["security_rules"]["custom_rules"].append(rule_dict)
    
    def configure_for_medical_environment(self):
        """Configure for medical AI agent environment."""
        self.set_environment_name("medical_ai_environment")
        self.add_scan_path("./medical_agents")
        self.add_scan_path("./healthcare_ai")
        
        # Enable medical-specific rules
        self.enable_rule("MED_001")
        self.enable_rule("DATA_EXF_001")
        self.enable_rule("PRIVACY_VIOLATION")
        
        # Configure for high security
        self.config["remediation"]["auto_remediate"] = False
        self.config["remediation"]["require_approval"] = True
        
        # Add compliance notifications
        if "integrations" not in self.config:
            self.config["integrations"] = {}
        self.config["integrations"]["compliance_notifications"] = {
            "enabled": True,
            "hipaa_compliance": True,
            "audit_logging": True
        }
    
    def configure_for_financial_environment(self):
        """Configure for financial AI agent environment."""
        self.set_environment_name("financial_ai_environment")
        self.add_scan_path("./financial_agents")
        self.add_scan_path("./banking_ai")
        
        # Enable financial-specific rules
        self.enable_rule("FIN_001")
        self.enable_rule("DATA_EXF_001")
        self.enable_rule("DATA_EXF_002")
        
        # Configure for high security
        self.config["remediation"]["auto_remediate"] = False
        self.config["remediation"]["require_approval"] = True
        
        # Add compliance notifications
        if "integrations" not in self.config:
            self.config["integrations"] = {}
        self.config["integrations"]["compliance_notifications"] = {
            "enabled": True,
            "pci_compliance": True,
            "sox_compliance": True,
            "audit_logging": True
        }
    
    def configure_for_development_environment(self):
        """Configure for development AI agent environment."""
        self.set_environment_name("development_ai_environment")
        self.add_scan_path("./dev_agents")
        self.add_scan_path("./code_assistants")
        
        # Enable development-specific rules
        self.enable_rule("SYS_MAN_001")
        self.enable_rule("SYS_MAN_002")
        self.enable_rule("MAL_INP_001")
        
        # Allow more automated remediation for dev
        self.config["remediation"]["auto_remediate"] = True
        self.config["remediation"]["require_approval"] = False
    
    def configure_for_production_environment(self):
        """Configure for production AI agent environment."""
        self.set_environment_name("production_ai_environment")
        
        # Enable all security rules
        all_rules = [
            "PROMPT_INJ_001", "PROMPT_INJ_002",
            "DATA_EXF_001", "DATA_EXF_002",
            "SYS_MAN_001", "SYS_MAN_002",
            "MED_001", "FIN_001",
            "RATE_001", "MAL_INP_001"
        ]
        for rule in all_rules:
            self.enable_rule(rule)
        
        # Strict remediation policies
        self.config["remediation"]["auto_remediate"] = False
        self.config["remediation"]["require_approval"] = True
        self.config["remediation"]["approval_timeout"] = 600  # 10 minutes
        
        # Enhanced monitoring
        self.config["monitoring"]["rate_limiting"]["requests_per_minute"] = 50
        self.config["monitoring"]["rate_limiting"]["burst_limit"] = 100
    
    def get_environment_presets(self) -> Dict[str, str]:
        """Get available environment presets."""
        return {
            "medical": "Medical AI Agent Environment",
            "financial": "Financial AI Agent Environment", 
            "development": "Development AI Agent Environment",
            "production": "Production AI Agent Environment",
            "custom": "Custom Configuration"
        }
    
    def apply_preset(self, preset_name: str):
        """Apply a configuration preset."""
        if preset_name == "medical":
            self.configure_for_medical_environment()
        elif preset_name == "financial":
            self.configure_for_financial_environment()
        elif preset_name == "development":
            self.configure_for_development_environment()
        elif preset_name == "production":
            self.configure_for_production_environment()
        else:
            raise ValueError(f"Unknown preset: {preset_name}")
        
        self.save_config()
    
    def validate_config(self) -> List[str]:
        """Validate the current configuration and return any issues."""
        issues = []
        
        # Check required fields
        if not self.config.get("environment", {}).get("name"):
            issues.append("Environment name is required")
        
        # Check scan paths exist
        scan_paths = self.get_scan_paths()
        for path in scan_paths:
            if not os.path.exists(path):
                issues.append(f"Scan path does not exist: {path}")
        
        # Check enabled rules
        enabled_rules = self.config.get("security_rules", {}).get("enabled_rules", [])
        if not enabled_rules:
            issues.append("No security rules are enabled")
        
        return issues
