"""
CLI/Process adapter for command-line based agents.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from .base_adapter import BaseAdapter
from ..models import AgentManifest, AdapterConfig

logger = logging.getLogger(__name__)


class CLIAdapter(BaseAdapter):
    """Adapter for agents that run as CLI tools or processes."""

    def __init__(self, manifest: AgentManifest, config: Optional[AdapterConfig] = None):
        super().__init__(manifest, config)

        self.command = manifest.command or self._build_default_command()
        self.use_docker = manifest.docker_image is not None
        self.docker_image = manifest.docker_image

        logger.info(f"CLI adapter initialized: {self.command}")

    def _build_default_command(self) -> str:
        """Build default command from manifest."""
        if self.manifest.language == 'Python':
            return f"python {self.manifest.file_path}"
        elif self.manifest.language == 'JavaScript':
            return f"node {self.manifest.file_path}"
        elif self.manifest.language == 'Go':
            return f"go run {self.manifest.file_path}"
        else:
            return f"./{self.manifest.file_path}"

    async def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke CLI tool.

        Args:
            input_data: Input data

        Returns:
            Output from CLI tool
        """
        # Transform input
        agent_input = self._transform_input(input_data)

        # Run command
        if self.use_docker:
            output = await self._run_in_docker(agent_input)
        else:
            output = await self._run_local(agent_input)

        # Parse and transform output
        result = self._parse_output(output)
        return self._transform_output(result)

    async def _run_local(self, input_data: Dict[str, Any]) -> str:
        """Run command locally."""
        # Write input to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(input_data, f)
            input_file = f.name

        try:
            # Build command with input file
            cmd = self._build_command(input_file)

            # Execute command
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env()
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Command timed out after {self.config.timeout}s")

            # Check return code
            if process.returncode != 0:
                raise Exception(f"Command failed with code {process.returncode}: {stderr.decode()}")

            return stdout.decode()

        finally:
            # Clean up temp file
            Path(input_file).unlink(missing_ok=True)

    async def _run_in_docker(self, input_data: Dict[str, Any]) -> str:
        """Run command in Docker container."""
        # Write input to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(input_data, f)
            input_file = f.name

        try:
            # Build docker command
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{input_file}:/input.json',
                self.docker_image,
                self.command, '/input.json'
            ]

            cmd_str = ' '.join(docker_cmd)

            # Execute docker command
            process = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for completion
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Docker command timed out after {self.config.timeout}s")

            if process.returncode != 0:
                raise Exception(f"Docker command failed: {stderr.decode()}")

            return stdout.decode()

        finally:
            Path(input_file).unlink(missing_ok=True)

    def _build_command(self, input_file: str) -> str:
        """Build complete command with input file."""
        # Check if command already has input file parameter
        if '{input}' in self.command:
            return self.command.replace('{input}', input_file)
        elif '--input' in self.command or '-i' in self.command:
            return f"{self.command} {input_file}"
        else:
            return f"{self.command} --input {input_file}"

    def _build_env(self) -> Dict[str, str]:
        """Build environment variables."""
        import os
        env = os.environ.copy()

        # Add manifest env vars
        for key, value in self.manifest.env_vars.items():
            env[key] = value

        return env

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse output from command."""
        # Try to parse as JSON
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            # Return as plain text
            return {"output": output.strip()}

    async def health_check(self) -> bool:
        """Check if command can be executed."""
        try:
            # Try to run a simple version check
            if self.use_docker:
                cmd = f"docker image inspect {self.docker_image}"
            else:
                # Extract base command (e.g., "python" from "python script.py")
                base_cmd = self.command.split()[0]
                cmd = f"{base_cmd} --version"

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(process.communicate(), timeout=5.0)
            return process.returncode == 0

        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False
