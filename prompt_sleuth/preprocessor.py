"""
Preprocessor for PromptSleuth.
Handles normalization and cleaning of prompts (Step B).
"""

import re
import html
from typing import Tuple
from .models import PromptInput


class PromptPreprocessor:
    """
    Preprocesses prompts before analysis.
    Normalizes spaces, decodes encodings, and removes metadata while
    preserving semantic content.
    """

    def __init__(self):
        # Patterns for cleaning
        self.excessive_whitespace = re.compile(r'\s+')
        self.http_headers_pattern = re.compile(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?HTTP/\d\.\d.*?\n\n',
            re.MULTILINE | re.DOTALL
        )

    def preprocess(self, prompt_input: PromptInput) -> PromptInput:
        """
        Preprocess the prompt input.

        Args:
            prompt_input: Raw prompt input

        Returns:
            Cleaned prompt input
        """
        system_prompt = self._clean_text(prompt_input.system_prompt)
        user_input = self._clean_text(prompt_input.user_input)

        # Ensure clear separation (critical for security)
        system_prompt = self._ensure_separation(system_prompt, "SYSTEM")
        user_input = self._ensure_separation(user_input, "USER")

        return PromptInput(
            system_prompt=system_prompt,
            user_input=user_input,
            metadata=prompt_input.metadata
        )

    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize text.

        Args:
            text: Raw text

        Returns:
            Cleaned text
        """
        if not text:
            return ""

        # Decode HTML entities
        text = html.unescape(text)

        # Remove HTTP headers if present
        text = self.http_headers_pattern.sub('', text)

        # Normalize whitespace (but preserve single newlines for structure)
        # Replace multiple spaces with single space
        lines = text.split('\n')
        cleaned_lines = []
        for line in lines:
            # Normalize spaces within line
            line = self.excessive_whitespace.sub(' ', line)
            line = line.strip()
            if line:  # Keep non-empty lines
                cleaned_lines.append(line)

        text = '\n'.join(cleaned_lines)

        # Remove null bytes and other control characters (except newlines)
        text = ''.join(char for char in text if char == '\n' or ord(char) >= 32)

        return text.strip()

    def _ensure_separation(self, text: str, label: str) -> str:
        """
        Ensure the prompt has clear separation marker.
        This prevents injection that tries to blur system/user boundaries.

        Args:
            text: Text to mark
            label: Label to add (SYSTEM or USER)

        Returns:
            Marked text
        """
        # Don't add marker if text is empty
        if not text:
            return text

        # Check if text already has a marker (avoid duplication)
        if text.startswith(f"[{label}]"):
            return text

        return f"[{label}]\n{text}"

    def validate_separation(self, prompt_input: PromptInput) -> bool:
        """
        Validate that system and user prompts are properly separated.

        Args:
            prompt_input: Prompt to validate

        Returns:
            True if separation is valid, False otherwise
        """
        system = prompt_input.system_prompt
        user = prompt_input.user_input

        # Check for attempts to inject system-like markers in user input
        suspicious_patterns = [
            r'\[SYSTEM\]',
            r'system\s*prompt\s*:',
            r'ignore\s+previous\s+instructions',
            r'disregard\s+above',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, user, re.IGNORECASE):
                return False

        return True

    def extract_potential_injections(self, text: str) -> list:
        """
        Extract potential injection markers from text.

        Args:
            text: Text to analyze

        Returns:
            List of potential injection patterns found
        """
        patterns = [
            (r'ignore\s+previous\s+instructions', 'ignore_previous'),
            (r'disregard\s+(all\s+)?above', 'disregard_above'),
            (r'forget\s+(everything|all|previous)', 'forget_previous'),
            (r'new\s+instructions?:', 'new_instructions'),
            (r'system\s*:\s*', 'system_override'),
            (r'\[SYSTEM\]', 'system_marker'),
            (r'--- END.*---', 'end_marker'),
        ]

        found = []
        for pattern, label in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(label)

        return found
