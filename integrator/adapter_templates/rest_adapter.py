"""
REST API adapter for HTTP-based agents.
"""

import aiohttp
from typing import Dict, Any, Optional
import logging

from .base_adapter import BaseAdapter
from ..models import AgentManifest, AdapterConfig

logger = logging.getLogger(__name__)


class RESTAdapter(BaseAdapter):
    """Adapter for agents exposing REST APIs."""

    def __init__(self, manifest: AgentManifest, config: Optional[AdapterConfig] = None):
        super().__init__(manifest, config)

        # Build base URL
        self.base_url = self._build_base_url()

        # Session for connection pooling
        self.session: Optional[aiohttp.ClientSession] = None

        logger.info(f"REST adapter initialized for {self.base_url}")

    def _build_base_url(self) -> str:
        """Build base URL from manifest."""
        if self.manifest.endpoint:
            if self.manifest.endpoint.startswith(('http://', 'https://')):
                return self.manifest.endpoint.rstrip('/')
            else:
                # Build URL from parts
                host = "localhost"
                port = self.manifest.port or 8000
                endpoint = self.manifest.endpoint
                return f"http://{host}:{port}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        else:
            # Default endpoint
            host = "localhost"
            port = self.manifest.port or 8000
            return f"http://{host}:{port}/invoke"

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke REST API endpoint.

        Args:
            input_data: Input data

        Returns:
            Response data from API
        """
        session = await self._get_session()

        # Transform input to agent's expected format
        agent_input = self._transform_input(input_data)

        # Add authentication if configured
        headers = self._build_headers()

        # Make HTTP request
        try:
            async with session.post(
                self.base_url,
                json=agent_input,
                headers=headers
            ) as response:
                if response.status >= 400:
                    error_text = await response.text()
                    raise Exception(f"HTTP {response.status}: {error_text}")

                # Parse response
                if response.content_type == 'application/json':
                    result = await response.json()
                else:
                    text = await response.text()
                    result = {"response": text}

                # Transform output to standard format
                return self._transform_output(result)

        except aiohttp.ClientError as e:
            logger.error(f"HTTP request failed: {e}")
            raise Exception(f"Failed to invoke agent: {e}")

    async def health_check(self) -> bool:
        """Check if API is reachable."""
        try:
            session = await self._get_session()

            # Try health check endpoint if specified
            health_url = self.manifest.health_check or self.base_url.rsplit('/', 1)[0] + '/health'

            async with session.get(health_url, timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                return response.status < 400

        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False

    def _build_headers(self) -> Dict[str, str]:
        """Build HTTP headers including authentication."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SOC-AI-Integrator/1.0"
        }

        # Add authentication based on manifest
        if self.manifest.auth_type == "api_key":
            api_key = self.manifest.env_vars.get("API_KEY", "")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

        elif self.manifest.auth_type == "basic":
            # Basic auth would go here
            pass

        return headers

    async def close(self):
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
