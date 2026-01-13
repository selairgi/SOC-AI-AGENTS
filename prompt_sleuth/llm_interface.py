"""
LLM Interface for PromptSleuth.
Handles communication with various LLM providers (OpenAI, Anthropic, Groq).
"""

import time
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
from .config import LLMConfig


class LLMInterface(ABC):
    """Abstract base class for LLM interfaces."""

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """
        Generate text from prompt.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional provider-specific parameters

        Returns:
            Generated text
        """
        pass

    def generate_with_retry(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """
        Generate with automatic retry logic.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional provider-specific parameters

        Returns:
            Generated text

        Raises:
            Exception: If all retries fail
        """
        last_error = None

        for attempt in range(self.config.max_retries):
            try:
                return self.generate(
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs
                )
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    # Exponential backoff
                    sleep_time = 2 ** attempt
                    time.sleep(sleep_time)

        raise Exception(f"LLM generation failed after {self.config.max_retries} attempts: {last_error}")


class OpenAIInterface(LLMInterface):
    """OpenAI API interface."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)

        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                timeout=config.timeout
            )
        except ImportError:
            raise ImportError("OpenAI package not installed. Run: pip install openai")

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """Generate using OpenAI API."""
        if max_tokens is None:
            max_tokens = self.config.max_tokens
        if temperature is None:
            temperature = self.config.temperature

        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )

        return response.choices[0].message.content


class AnthropicInterface(LLMInterface):
    """Anthropic (Claude) API interface."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)

        try:
            from anthropic import Anthropic
            self.client = Anthropic(
                api_key=config.api_key,
                timeout=config.timeout
            )
        except ImportError:
            raise ImportError("Anthropic package not installed. Run: pip install anthropic")

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """Generate using Anthropic API."""
        if max_tokens is None:
            max_tokens = self.config.max_tokens
        if temperature is None:
            temperature = self.config.temperature

        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "user", "content": prompt}
            ],
            **kwargs
        )

        return response.content[0].text


class GroqInterface(LLMInterface):
    """Groq API interface."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)

        try:
            from groq import Groq
            self.client = Groq(
                api_key=config.api_key,
            )
        except ImportError:
            raise ImportError("Groq package not installed. Run: pip install groq")

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """Generate using Groq API."""
        if max_tokens is None:
            max_tokens = self.config.max_tokens
        if temperature is None:
            temperature = self.config.temperature

        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )

        return response.choices[0].message.content


def create_llm_interface(config: LLMConfig) -> LLMInterface:
    """
    Factory function to create appropriate LLM interface.

    Args:
        config: LLM configuration

    Returns:
        LLM interface instance

    Raises:
        ValueError: If provider is unsupported
    """
    if config.provider == "openai":
        return OpenAIInterface(config)
    elif config.provider == "anthropic":
        return AnthropicInterface(config)
    elif config.provider == "groq":
        return GroqInterface(config)
    else:
        raise ValueError(f"Unsupported LLM provider: {config.provider}")
