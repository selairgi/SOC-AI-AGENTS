"""
Logging configuration for SOC AI Agents.
"""

import logging


def setup_logging(log_level: str = "INFO", log_format: str = None):
    """Setup logging configuration with structured format"""
    if log_format is None:
        log_format = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Set specific loggers
    logging.getLogger("SOCBuilder").setLevel(logging.INFO)
    logging.getLogger("SOCAnalyst").setLevel(logging.INFO)
    logging.getLogger("Remediator").setLevel(logging.INFO)
    
    return logging.getLogger(__name__)
