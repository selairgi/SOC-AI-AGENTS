"""
Logging and Audit system for PromptSleuth.
Handles structured logging of detections and audits (Step G).
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from .models import PromptInput, DetectionResult
from .config import LoggingConfig


class PromptSleuthLogger:
    """
    Logger for PromptSleuth detections and audit trail.
    Supports both structured JSON logging and traditional text logs.
    """

    def __init__(self, config: LoggingConfig):
        self.config = config
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup logging infrastructure."""
        logger = logging.getLogger("PromptSleuth")
        logger.setLevel(getattr(logging, self.config.log_level))

        # Remove existing handlers
        logger.handlers = []

        if not self.config.enable_logging:
            logger.addHandler(logging.NullHandler())
            return logger

        # File handler
        if self.config.log_file:
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path, encoding='utf-8')
            file_handler.setLevel(getattr(logging, self.config.log_level))

            if self.config.structured_logging:
                # JSON formatter
                formatter = JSONFormatter()
            else:
                # Standard formatter
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )

            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        # Console handler (always non-JSON for readability)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)  # Only warnings and errors to console
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        return logger

    def log_detection(
        self,
        prompt_input: PromptInput,
        result: DetectionResult,
        processing_time: Optional[float] = None
    ):
        """
        Log a detection result.

        Args:
            prompt_input: Original prompt input
            result: Detection result
            processing_time: Time taken to process (seconds)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "detection": {
                "is_injection": result.is_injection,
                "confidence": result.confidence,
                "suspicious_tasks": result.suspicious_tasks,
                "tasks_parent": result.tasks_parent,
                "tasks_child": result.tasks_child,
                "explanation": result.explanation,
                "metadata": result.metadata
            }
        }

        if processing_time is not None:
            log_entry["processing_time_seconds"] = processing_time

        # Include raw prompts if configured
        if self.config.log_raw_prompts:
            log_entry["prompts"] = {
                "system_prompt": prompt_input.system_prompt,
                "user_input": prompt_input.user_input
            }
        else:
            # Just log hashes/lengths for privacy
            log_entry["prompts"] = {
                "system_prompt_length": len(prompt_input.system_prompt),
                "user_input_length": len(prompt_input.user_input)
            }

        # Log appropriate level
        if result.is_injection:
            self.logger.warning(
                f"INJECTION DETECTED",
                extra={"data": log_entry}
            )
        else:
            self.logger.info(
                f"No injection detected",
                extra={"data": log_entry}
            )

    def log_error(self, error: Exception, context: Optional[dict] = None):
        """
        Log an error.

        Args:
            error: Exception that occurred
            context: Additional context information
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "error": {
                "type": type(error).__name__,
                "message": str(error),
                "context": context or {}
            }
        }

        self.logger.error(
            f"Error: {error}",
            extra={"data": log_entry},
            exc_info=True
        )

    def log_info(self, message: str, data: Optional[dict] = None):
        """
        Log informational message.

        Args:
            message: Log message
            data: Additional data
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "data": data or {}
        }

        self.logger.info(message, extra={"data": log_entry})

    def log_warning(self, message: str, data: Optional[dict] = None):
        """
        Log warning message.

        Args:
            message: Warning message
            data: Additional data
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "data": data or {}
        }

        self.logger.warning(message, extra={"data": log_entry})


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra data if present
        if hasattr(record, 'data'):
            log_obj.update(record.data)

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj, ensure_ascii=False)
