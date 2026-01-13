"""
PromptSleuth - Main API for Prompt Injection Detection.
Orchestrates the complete detection pipeline.
"""

import time
from typing import Optional
from .models import PromptInput, DetectionResult, TaskGraph
from .config import PromptSleuthConfig
from .preprocessor import PromptPreprocessor
from .task_extractor import TaskExtractor
from .graph_builder import GraphBuilder
from .detector import InjectionDetector
from .logger import PromptSleuthLogger
from .llm_interface import create_llm_interface


class PromptSleuth:
    """
    Main PromptSleuth system for detecting prompt injections.

    Implements the complete pipeline:
    1. Preprocessing and normalization
    2. Task extraction from system and user prompts
    3. Task relationship graph construction
    4. Injection detection via graph analysis
    5. Logging and audit
    """

    def __init__(self, config: Optional[PromptSleuthConfig] = None):
        """
        Initialize PromptSleuth.

        Args:
            config: Configuration (uses default if None)
        """
        self.config = config or PromptSleuthConfig.default()

        # Initialize components
        self.preprocessor = PromptPreprocessor()
        self.llm_interface = create_llm_interface(self.config.llm)
        self.task_extractor = TaskExtractor(self.config, self.llm_interface)
        self.graph_builder = GraphBuilder(self.config, self.llm_interface)
        self.detector = InjectionDetector(self.config)
        self.logger = PromptSleuthLogger(self.config.logging)

        self.logger.log_info("PromptSleuth initialized", {
            "llm_provider": self.config.llm.provider,
            "llm_model": self.config.llm.model
        })

    def check_prompt(
        self,
        system_prompt: str,
        user_input: str,
        metadata: Optional[dict] = None
    ) -> DetectionResult:
        """
        Check a prompt for injection attempts.

        This is the main API method.

        Args:
            system_prompt: System prompt / instructions
            user_input: User input / query
            metadata: Optional metadata for logging

        Returns:
            Detection result
        """
        start_time = time.time()

        try:
            # Create prompt input
            prompt_input = PromptInput(
                system_prompt=system_prompt,
                user_input=user_input,
                metadata=metadata
            )

            # Step B: Preprocess
            prompt_input = self.preprocessor.preprocess(prompt_input)

            # Validate separation
            if not self.preprocessor.validate_separation(prompt_input):
                self.logger.log_warning("Suspicious prompt structure detected")

            # Step C: Extract tasks
            parent_tasks, child_tasks = self.task_extractor.extract_tasks(prompt_input)

            self.logger.log_info(
                f"Extracted {len(parent_tasks)} parent tasks, {len(child_tasks)} child tasks"
            )

            # Handle edge cases
            if not parent_tasks or not child_tasks:
                result = DetectionResult(
                    is_injection=False,
                    tasks_parent=[t.text for t in parent_tasks],
                    tasks_child=[t.text for t in child_tasks],
                    relations=[],
                    explanation="Insufficient tasks for analysis"
                )
                processing_time = time.time() - start_time
                self.logger.log_detection(prompt_input, result, processing_time)
                return result

            # Step D: Build task relationship graph
            graph = self.graph_builder.build_graph(parent_tasks, child_tasks)

            # Analyze graph
            graph_analysis = self.graph_builder.analyze_graph(graph)
            self.logger.log_info("Graph analysis", graph_analysis)

            # Step E: Detect injection
            result = self.detector.detect(graph)

            # Add metadata
            result.metadata.update(graph_analysis)
            if metadata:
                result.metadata["input_metadata"] = metadata

            # Log result
            processing_time = time.time() - start_time
            result.metadata["processing_time_seconds"] = processing_time

            self.logger.log_detection(prompt_input, result, processing_time)

            return result

        except Exception as e:
            self.logger.log_error(e, {"system_prompt_len": len(system_prompt), "user_input_len": len(user_input)})
            raise

    def check_prompt_simple(self, user_input: str, system_prompt: str = "You are a helpful assistant.") -> bool:
        """
        Simplified check method that returns just True/False.

        Args:
            user_input: User input to check
            system_prompt: System prompt (default: generic assistant)

        Returns:
            True if injection detected, False otherwise
        """
        result = self.check_prompt(system_prompt, user_input)
        return result.is_injection

    def get_task_graph(self, system_prompt: str, user_input: str) -> TaskGraph:
        """
        Get the task relationship graph without running detection.
        Useful for debugging and visualization.

        Args:
            system_prompt: System prompt
            user_input: User input

        Returns:
            Task graph
        """
        prompt_input = PromptInput(
            system_prompt=system_prompt,
            user_input=user_input
        )

        prompt_input = self.preprocessor.preprocess(prompt_input)
        parent_tasks, child_tasks = self.task_extractor.extract_tasks(prompt_input)
        graph = self.graph_builder.build_graph(parent_tasks, child_tasks)

        return graph


# Convenience functions for quick usage

def check_prompt(
    system_prompt: str,
    user_input: str,
    config: Optional[PromptSleuthConfig] = None
) -> DetectionResult:
    """
    Convenience function to check a prompt without creating PromptSleuth instance.

    Args:
        system_prompt: System prompt
        user_input: User input
        config: Optional configuration

    Returns:
        Detection result
    """
    sleuth = PromptSleuth(config)
    return sleuth.check_prompt(system_prompt, user_input)


def is_injection(
    user_input: str,
    system_prompt: str = "You are a helpful assistant.",
    config: Optional[PromptSleuthConfig] = None
) -> bool:
    """
    Convenience function to quickly check if input is injection.

    Args:
        user_input: User input
        system_prompt: System prompt (default: generic)
        config: Optional configuration

    Returns:
        True if injection detected, False otherwise
    """
    result = check_prompt(system_prompt, user_input, config)
    return result.is_injection
