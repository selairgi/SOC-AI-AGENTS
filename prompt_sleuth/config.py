"""
Configuration for PromptSleuth system.
Manages thresholds, LLM settings, and detection parameters.
"""

from dataclasses import dataclass, field
from typing import Optional, Literal
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass
class LLMConfig:
    """Configuration for LLM API calls."""
    provider: Literal["openai", "anthropic", "groq"] = "openai"
    model: str = "gpt-4o-mini"  # Default to fast, cost-effective model
    api_key: Optional[str] = None
    timeout: int = 5  # seconds
    max_retries: int = 3
    temperature: float = 0.0  # Deterministic for security
    max_tokens: int = 500

    def __post_init__(self):
        if self.api_key is None:
            # Try to load from environment
            if self.provider == "openai":
                self.api_key = os.getenv("OPENAI_API_KEY")
            elif self.provider == "anthropic":
                self.api_key = os.getenv("ANTHROPIC_API_KEY")
            elif self.provider == "groq":
                self.api_key = os.getenv("GROQ_API_KEY")


@dataclass
class DetectionConfig:
    """Configuration for detection logic."""
    # Threshold for uncertain confidence (below this = treat as uncertain)
    uncertain_threshold: float = 0.6

    # If proportion of uncertain relations exceeds this, flag for human review
    uncertain_proportion_threshold: float = 0.2

    # Enable/disable explanations (increases latency but improves interpretability)
    enable_explanations: bool = True

    # Use ensemble voting (multiple LLM calls, majority vote)
    enable_ensemble: bool = False
    ensemble_votes: int = 3  # Number of votes if ensemble enabled

    # Minimum confidence for injection detection
    min_injection_confidence: float = 0.7


@dataclass
class TaskExtractionConfig:
    """Configuration for task extraction."""
    # Task length constraints (in words)
    min_task_words: int = 2
    max_task_words: int = 5

    # Maximum number of tasks to extract per prompt
    max_tasks_per_prompt: int = 10

    # Enable task deduplication
    enable_deduplication: bool = True

    # Similarity threshold for merging similar tasks (0.0 to 1.0)
    similarity_threshold: float = 0.85


@dataclass
class LoggingConfig:
    """Configuration for logging and audit."""
    enable_logging: bool = True
    log_file: Optional[str] = "prompt_sleuth_audit.log"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Store raw prompts in logs (careful with sensitive data)
    log_raw_prompts: bool = False

    # Enable structured JSON logging
    structured_logging: bool = True


@dataclass
class PromptSleuthConfig:
    """Master configuration for PromptSleuth system."""
    llm: LLMConfig = field(default_factory=LLMConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    task_extraction: TaskExtractionConfig = field(default_factory=TaskExtractionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def default(cls) -> "PromptSleuthConfig":
        """Create default configuration."""
        return cls()

    @classmethod
    def fast_mode(cls) -> "PromptSleuthConfig":
        """Configuration optimized for speed (lower latency)."""
        config = cls.default()
        config.llm.model = "gpt-4o-mini"
        config.llm.timeout = 3
        config.detection.enable_explanations = False
        config.detection.enable_ensemble = False
        return config

    @classmethod
    def accurate_mode(cls) -> "PromptSleuthConfig":
        """Configuration optimized for accuracy (higher latency)."""
        config = cls.default()
        config.llm.model = "gpt-4o"
        config.llm.timeout = 10
        config.detection.enable_explanations = True
        config.detection.enable_ensemble = True
        config.detection.ensemble_votes = 3
        return config


# Default global config
DEFAULT_CONFIG = PromptSleuthConfig.default()
