"""
Base adapter interface for external agent integration.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import asyncio
import logging

from ..models import AgentManifest, AdapterConfig, InvocationResult

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """Base class for all agent adapters."""

    def __init__(self, manifest: AgentManifest, config: Optional[AdapterConfig] = None):
        self.manifest = manifest
        self.config = config or self._default_config(manifest)

        # Statistics
        self.total_invocations = 0
        self.successful_invocations = 0
        self.failed_invocations = 0
        self.total_execution_time = 0.0
        self.last_invoked_at: Optional[datetime] = None

        logger.info(f"Initialized {self.__class__.__name__} for {manifest.agent_id}")

    def _default_config(self, manifest: AgentManifest) -> AdapterConfig:
        """Create default adapter configuration."""
        return AdapterConfig(
            adapter_id=f"{manifest.agent_id}-adapter",
            manifest=manifest,
            template_name=self.__class__.__name__.lower().replace('adapter', ''),
            retry_enabled=True,
            max_retries=3,
            retry_delay=1.0,
            circuit_breaker_enabled=True,
            timeout=30.0,
            input_validation=True,
            output_sanitization=True,
        )

    @abstractmethod
    async def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke the external agent with input data.

        Args:
            input_data: Input data in standardized format

        Returns:
            Output data in standardized format

        Raises:
            Exception: If invocation fails
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if agent is healthy and reachable.

        Returns:
            True if healthy, False otherwise
        """
        pass

    async def invoke_with_safety(self, input_data: Dict[str, Any]) -> InvocationResult:
        """
        Invoke agent with safety checks, retries, and monitoring.

        Args:
            input_data: Input data

        Returns:
            InvocationResult with success/failure info
        """
        request_id = f"{self.manifest.agent_id}-{datetime.now().timestamp()}"
        start_time = datetime.now()

        try:
            # Validate input
            if self.config.input_validation:
                self._validate_input(input_data)

            # Apply rate limiting
            if self.config.rate_limit:
                await self._check_rate_limit()

            # Invoke with retry logic
            if self.config.retry_enabled:
                output_data = await self._invoke_with_retry(input_data)
            else:
                output_data = await self.invoke(input_data)

            # Sanitize output
            if self.config.output_sanitization:
                output_data = self._sanitize_output(output_data)

            # Update statistics
            execution_time = (datetime.now() - start_time).total_seconds()
            self.total_invocations += 1
            self.successful_invocations += 1
            self.total_execution_time += execution_time
            self.last_invoked_at = datetime.now()

            return InvocationResult(
                request_id=request_id,
                agent_id=self.manifest.agent_id,
                capability="invoke",
                success=True,
                output_data=output_data,
                execution_time=execution_time,
            )

        except Exception as e:
            logger.error(f"Invocation failed for {self.manifest.agent_id}: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()
            self.total_invocations += 1
            self.failed_invocations += 1

            return InvocationResult(
                request_id=request_id,
                agent_id=self.manifest.agent_id,
                capability="invoke",
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    async def _invoke_with_retry(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke with retry logic."""
        last_exception = None

        for attempt in range(self.config.max_retries):
            try:
                # Apply timeout
                return await asyncio.wait_for(
                    self.invoke(input_data),
                    timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout on attempt {attempt + 1}")
                last_exception = TimeoutError(f"Invocation timed out after {self.config.timeout}s")
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                last_exception = e

            # Wait before retry (exponential backoff)
            if attempt < self.config.max_retries - 1:
                wait_time = self.config.retry_delay * (2 ** attempt)
                await asyncio.sleep(wait_time)

        # All retries failed
        raise last_exception or Exception("All retry attempts failed")

    def _validate_input(self, input_data: Dict[str, Any]) -> None:
        """Validate input data against schema."""
        if not isinstance(input_data, dict):
            raise ValueError("Input must be a dictionary")

        # Additional validation based on manifest schema
        if self.manifest.input_schema:
            # TODO: Implement JSON schema validation
            pass

    def _sanitize_output(self, output_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize output data."""
        if not isinstance(output_data, dict):
            return {"result": str(output_data)}

        # Remove potentially sensitive fields
        sensitive_keys = ['password', 'secret', 'token', 'api_key', 'private_key']
        sanitized = {}

        for key, value in output_data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized

    async def _check_rate_limit(self) -> None:
        """Check and enforce rate limits."""
        # TODO: Implement rate limiting logic
        pass

    def _transform_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform input from standard format to agent-specific format.

        Override in subclasses for custom transformations.
        """
        if not self.config.input_transform:
            return data

        transformed = {}
        for source_key, target_key in self.config.input_transform.items():
            if source_key in data:
                transformed[target_key] = data[source_key]

        return transformed or data

    def _transform_output(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform output from agent-specific format to standard format.

        Override in subclasses for custom transformations.
        """
        if not self.config.output_transform:
            return data

        transformed = {}
        for source_key, target_key in self.config.output_transform.items():
            if source_key in data:
                transformed[target_key] = data[source_key]

        return transformed or data

    def get_statistics(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        avg_time = 0.0
        if self.total_invocations > 0:
            avg_time = self.total_execution_time / self.total_invocations

        return {
            'agent_id': self.manifest.agent_id,
            'total_invocations': self.total_invocations,
            'successful_invocations': self.successful_invocations,
            'failed_invocations': self.failed_invocations,
            'success_rate': self.successful_invocations / max(self.total_invocations, 1) * 100,
            'average_execution_time': avg_time,
            'last_invoked_at': self.last_invoked_at.isoformat() if self.last_invoked_at else None,
        }
