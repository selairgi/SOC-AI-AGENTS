"""
Schema validation for SOC AI Agents.
Provides JSON schema validation for alerts and playbooks.
"""

import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

try:
    from jsonschema import validate, ValidationError, Draft7Validator
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    # Create dummy classes for when jsonschema is not available
    class ValidationError(Exception):
        pass
    class Draft7Validator:
        @staticmethod
        def check_schema(schema):
            pass


@dataclass
class ValidationResult:
    """Result of schema validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str] = None


class SchemaValidator:
    """JSON schema validator for SOC components."""
    
    def __init__(self):
        self.logger = logging.getLogger("SchemaValidator")
        if not JSONSCHEMA_AVAILABLE:
            self.logger.warning("jsonschema not available. Schema validation will be disabled.")
        self._schemas = self._load_schemas()
    
    def _load_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Load JSON schemas for validation."""
        return {
            "alert": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["id", "timestamp", "severity", "title", "description", "threat_type"],
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9._-]+$",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "timestamp": {
                        "type": "number",
                        "minimum": 0
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"]
                    },
                    "title": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200
                    },
                    "description": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000
                    },
                    "threat_type": {
                        "type": "string",
                        "enum": [
                            "prompt_injection", "data_exfiltration", "unauthorized_access",
                            "malicious_input", "system_manipulation", "privacy_violation",
                            "rate_limit_abuse", "model_poisoning"
                        ]
                    },
                    "agent_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "rule_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "evidence": {
                        "type": "object",
                        "additionalProperties": True
                    },
                    "correlated": {
                        "type": "boolean"
                    },
                    "false_positive_probability": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0
                    }
                },
                "additionalProperties": False
            },
            
            "playbook": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["action", "target", "justification", "owner"],
                "properties": {
                    "action": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 50
                    },
                    "target": {
                        "type": "string",
                        "maxLength": 500
                    },
                    "justification": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000
                    },
                    "owner": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9._-]+$",
                        "maxLength": 100
                    },
                    "threat_type": {
                        "type": ["string", "null"],
                        "enum": [
                            "prompt_injection", "data_exfiltration", "unauthorized_access",
                            "malicious_input", "system_manipulation", "privacy_violation",
                            "rate_limit_abuse", "model_poisoning", None
                        ]
                    },
                    "agent_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "metadata": {
                        "type": "object",
                        "properties": {
                            "actions": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": 100
                                },
                                "maxItems": 20
                            },
                            "alert_id": {
                                "type": "string",
                                "pattern": "^[a-zA-Z0-9._-]+$"
                            },
                            "threat_type": {
                                "type": "string"
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"]
                            },
                            "analysis_timestamp": {
                                "type": "number",
                                "minimum": 0
                            },
                            "auto_generated": {
                                "type": "boolean"
                            },
                            "confidence": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0
                            }
                        },
                        "additionalProperties": True
                    }
                },
                "additionalProperties": False
            },
            
            "log_entry": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["timestamp", "source", "message"],
                "properties": {
                    "timestamp": {
                        "type": "number",
                        "minimum": 0
                    },
                    "source": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "message": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 2000
                    },
                    "agent_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "user_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "session_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "src_ip": {
                        "type": ["string", "null"],
                        "pattern": "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    },
                    "dst_ip": {
                        "type": ["string", "null"],
                        "pattern": "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    },
                    "request_id": {
                        "type": ["string", "null"],
                        "pattern": "^[a-zA-Z0-9._-]*$",
                        "maxLength": 100
                    },
                    "response_time": {
                        "type": ["number", "null"],
                        "minimum": 0
                    },
                    "status_code": {
                        "type": ["integer", "null"],
                        "minimum": 100,
                        "maximum": 599
                    },
                    "extra": {
                        "type": "object",
                        "additionalProperties": True
                    }
                },
                "additionalProperties": False
            }
        }
    
    def validate_alert(self, alert_data: Dict[str, Any]) -> ValidationResult:
        """Validate alert data against schema."""
        if not JSONSCHEMA_AVAILABLE:
            self.logger.warning("jsonschema not available, skipping validation")
            return ValidationResult(is_valid=True, errors=[])
        try:
            validate(instance=alert_data, schema=self._schemas["alert"])
            return ValidationResult(is_valid=True, errors=[])
        except ValidationError as e:
            errors = [f"Alert validation error: {e.message}"]
            return ValidationResult(is_valid=False, errors=errors)
        except Exception as e:
            self.logger.error(f"Unexpected error validating alert: {e}")
            return ValidationResult(is_valid=False, errors=[f"Unexpected validation error: {e}"])
    
    def validate_playbook(self, playbook_data: Dict[str, Any]) -> ValidationResult:
        """Validate playbook data against schema."""
        if not JSONSCHEMA_AVAILABLE:
            self.logger.warning("jsonschema not available, skipping validation")
            return ValidationResult(is_valid=True, errors=[])
        try:
            validate(instance=playbook_data, schema=self._schemas["playbook"])
            return ValidationResult(is_valid=True, errors=[])
        except ValidationError as e:
            errors = [f"Playbook validation error: {e.message}"]
            return ValidationResult(is_valid=False, errors=errors)
        except Exception as e:
            self.logger.error(f"Unexpected error validating playbook: {e}")
            return ValidationResult(is_valid=False, errors=[f"Unexpected validation error: {e}"])
    
    def validate_log_entry(self, log_data: Dict[str, Any]) -> ValidationResult:
        """Validate log entry data against schema."""
        if not JSONSCHEMA_AVAILABLE:
            self.logger.warning("jsonschema not available, skipping validation")
            return ValidationResult(is_valid=True, errors=[])
        try:
            validate(instance=log_data, schema=self._schemas["log_entry"])
            return ValidationResult(is_valid=True, errors=[])
        except ValidationError as e:
            errors = [f"Log entry validation error: {e.message}"]
            return ValidationResult(is_valid=False, errors=errors)
        except Exception as e:
            self.logger.error(f"Unexpected error validating log entry: {e}")
            return ValidationResult(is_valid=False, errors=[f"Unexpected validation error: {e}"])
    
    def validate_json_string(self, json_string: str, schema_type: str) -> ValidationResult:
        """Validate a JSON string against a schema."""
        try:
            data = json.loads(json_string)
            if schema_type == "alert":
                return self.validate_alert(data)
            elif schema_type == "playbook":
                return self.validate_playbook(data)
            elif schema_type == "log_entry":
                return self.validate_log_entry(data)
            else:
                return ValidationResult(is_valid=False, errors=[f"Unknown schema type: {schema_type}"])
        except json.JSONDecodeError as e:
            return ValidationResult(is_valid=False, errors=[f"Invalid JSON: {e}"])
        except Exception as e:
            return ValidationResult(is_valid=False, errors=[f"Unexpected error: {e}"])
    
    def get_schema(self, schema_type: str) -> Optional[Dict[str, Any]]:
        """Get schema definition for a type."""
        return self._schemas.get(schema_type)
    
    def add_custom_schema(self, schema_type: str, schema: Dict[str, Any]) -> bool:
        """Add a custom schema."""
        if not JSONSCHEMA_AVAILABLE:
            self.logger.warning("jsonschema not available, cannot validate custom schema")
            self._schemas[schema_type] = schema
            return True
        try:
            # Validate the schema itself
            Draft7Validator.check_schema(schema)
            self._schemas[schema_type] = schema
            self.logger.info(f"Added custom schema: {schema_type}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add custom schema {schema_type}: {e}")
            return False
