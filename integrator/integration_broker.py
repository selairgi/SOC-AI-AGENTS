"""
Integration Broker - Orchestrates and routes messages between SOC agents and external agents.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from .models import (
    AgentManifest, AdapterConfig, RegisteredAgent,
    InvocationRequest, InvocationResult, IntegrationMetrics, InterfaceType
)
from .adapter_templates import BaseAdapter, RESTAdapter, MessageQueueAdapter, CLIAdapter

logger = logging.getLogger(__name__)


class IntegrationBroker:
    """
    Central broker for managing external agent integrations.

    Responsibilities:
    - Register and maintain agent registry
    - Route invocation requests to appropriate agents
    - Enforce policies and permissions
    - Track telemetry and metrics
    - Handle agent health monitoring
    """

    def __init__(self):
        self.registry: Dict[str, RegisteredAgent] = {}
        self.metrics = IntegrationMetrics()
        self._health_check_task: Optional[asyncio.Task] = None

        logger.info("Integration Broker initialized")

    async def start(self):
        """Start the broker and background tasks."""
        logger.info("Starting Integration Broker")

        # Start health check task
        self._health_check_task = asyncio.create_task(self._health_check_loop())

    async def stop(self):
        """Stop the broker and cleanup."""
        logger.info("Stopping Integration Broker")

        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        # Close all adapters
        for registered_agent in self.registry.values():
            adapter = registered_agent.adapter_instance
            if hasattr(adapter, 'close'):
                try:
                    await adapter.close()
                except Exception as e:
                    logger.error(f"Error closing adapter {registered_agent.manifest.agent_id}: {e}")

    def register_agent(
        self,
        manifest: AgentManifest,
        adapter_config: Optional[AdapterConfig] = None
    ) -> str:
        """
        Register an external agent with the broker.

        Args:
            manifest: Agent manifest
            adapter_config: Optional adapter configuration

        Returns:
            agent_id of registered agent
        """
        logger.info(f"Registering agent: {manifest.agent_id}")

        # Create appropriate adapter
        adapter = self._create_adapter(manifest, adapter_config)

        # Create registered agent
        registered_agent = RegisteredAgent(
            manifest=manifest,
            adapter_config=adapter_config or adapter.config,
            adapter_instance=adapter
        )

        # Add to registry
        self.registry[manifest.agent_id] = registered_agent

        # Update metrics
        self.metrics.total_agents += 1
        self.metrics.healthy_agents += 1
        self.metrics.agent_metrics[manifest.agent_id] = {
            'registered_at': datetime.now().isoformat(),
            'invocations': 0,
            'errors': 0,
            'total_cost': 0.0
        }

        logger.info(f"Agent {manifest.agent_id} registered successfully")
        return manifest.agent_id

    def _create_adapter(
        self,
        manifest: AgentManifest,
        config: Optional[AdapterConfig]
    ) -> BaseAdapter:
        """Create appropriate adapter based on interface type."""
        interface_type = manifest.interface_type

        if interface_type == InterfaceType.REST:
            return RESTAdapter(manifest, config)
        elif interface_type == InterfaceType.MESSAGE_QUEUE:
            return MessageQueueAdapter(manifest, config)
        elif interface_type == InterfaceType.CLI:
            return CLIAdapter(manifest, config)
        else:
            # Default to CLI adapter
            logger.warning(f"Unknown interface type {interface_type}, using CLI adapter")
            return CLIAdapter(manifest, config)

    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent from the broker.

        Args:
            agent_id: ID of agent to unregister

        Returns:
            True if unregistered, False if not found
        """
        if agent_id in self.registry:
            logger.info(f"Unregistering agent: {agent_id}")
            del self.registry[agent_id]
            self.metrics.total_agents -= 1
            return True
        return False

    async def invoke_agent(
        self,
        agent_id: str,
        capability: str,
        input_data: Dict[str, Any],
        requester_id: str = "soc_system"
    ) -> InvocationResult:
        """
        Invoke an external agent capability.

        Args:
            agent_id: ID of agent to invoke
            capability: Capability/function to invoke
            input_data: Input data for invocation
            requester_id: ID of requester

        Returns:
            InvocationResult
        """
        logger.info(f"Invoking agent {agent_id} capability {capability}")

        # Check if agent exists
        if agent_id not in self.registry:
            return InvocationResult(
                request_id=f"req-{datetime.now().timestamp()}",
                agent_id=agent_id,
                capability=capability,
                success=False,
                error=f"Agent {agent_id} not found in registry"
            )

        registered_agent = self.registry[agent_id]

        # Check if agent is healthy
        if not registered_agent.is_healthy:
            logger.warning(f"Agent {agent_id} is unhealthy, attempting invocation anyway")

        # TODO: Check policies here
        # if not await self._check_policy(agent_id, capability, requester_id):
        #     return InvocationResult(success=False, error="Policy denied")

        # Invoke adapter
        try:
            adapter = registered_agent.adapter_instance
            result = await adapter.invoke_with_safety(input_data)

            # Update agent metrics
            registered_agent.total_invocations += 1
            registered_agent.last_invoked_at = datetime.now()

            if result.success:
                registered_agent.total_invocations += 1
            else:
                registered_agent.total_errors += 1

            # Update broker metrics
            self.metrics.total_invocations += 1
            if result.success:
                self.metrics.successful_invocations += 1
            else:
                self.metrics.failed_invocations += 1

            # Update agent-specific metrics
            if agent_id in self.metrics.agent_metrics:
                self.metrics.agent_metrics[agent_id]['invocations'] += 1
                if not result.success:
                    self.metrics.agent_metrics[agent_id]['errors'] += 1

            return result

        except Exception as e:
            logger.error(f"Error invoking agent {agent_id}: {e}")
            registered_agent.total_errors += 1
            self.metrics.failed_invocations += 1

            return InvocationResult(
                request_id=f"req-{datetime.now().timestamp()}",
                agent_id=agent_id,
                capability=capability,
                success=False,
                error=str(e)
            )

    def discover_agents_by_capability(self, capability: str) -> List[str]:
        """
        Find agents that can handle a specific capability.

        Args:
            capability: Capability to search for

        Returns:
            List of agent IDs that have the capability
        """
        matching_agents = []

        for agent_id, registered_agent in self.registry.items():
            if capability in registered_agent.manifest.capabilities:
                matching_agents.append(agent_id)

        logger.debug(f"Found {len(matching_agents)} agents with capability {capability}")
        return matching_agents

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a registered agent."""
        if agent_id not in self.registry:
            return None

        registered_agent = self.registry[agent_id]
        manifest = registered_agent.manifest

        return {
            'agent_id': manifest.agent_id,
            'name': manifest.name,
            'description': manifest.description,
            'capabilities': manifest.capabilities,
            'interface_type': manifest.interface_type.value,
            'framework': manifest.framework.value,
            'security_level': manifest.security_level.value,
            'is_healthy': registered_agent.is_healthy,
            'total_invocations': registered_agent.total_invocations,
            'total_errors': registered_agent.total_errors,
            'average_latency': registered_agent.average_latency,
            'registered_at': registered_agent.registered_at.isoformat(),
        }

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all registered agents."""
        return [
            self.get_agent_info(agent_id)
            for agent_id in self.registry.keys()
        ]

    def get_metrics(self) -> Dict[str, Any]:
        """Get integration broker metrics."""
        return {
            'total_agents': self.metrics.total_agents,
            'healthy_agents': self.metrics.healthy_agents,
            'total_invocations': self.metrics.total_invocations,
            'successful_invocations': self.metrics.successful_invocations,
            'failed_invocations': self.metrics.failed_invocations,
            'success_rate': (
                self.metrics.successful_invocations / max(self.metrics.total_invocations, 1) * 100
            ),
            'total_cost': self.metrics.total_cost,
            'average_latency': self.metrics.average_latency,
            'start_time': self.metrics.start_time.isoformat(),
            'last_updated': datetime.now().isoformat(),
            'agent_metrics': self.metrics.agent_metrics
        }

    async def _health_check_loop(self):
        """Background task to check agent health."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                logger.debug("Running health checks on all agents")
                healthy_count = 0

                for agent_id, registered_agent in self.registry.items():
                    try:
                        adapter = registered_agent.adapter_instance
                        is_healthy = await adapter.health_check()

                        registered_agent.is_healthy = is_healthy
                        registered_agent.last_health_check = datetime.now()

                        if is_healthy:
                            healthy_count += 1
                        else:
                            logger.warning(f"Agent {agent_id} health check failed")

                    except Exception as e:
                        logger.error(f"Health check error for {agent_id}: {e}")
                        registered_agent.is_healthy = False

                # Update metrics
                self.metrics.healthy_agents = healthy_count

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")

    # Future: Policy enforcement methods
    async def _check_policy(
        self,
        agent_id: str,
        capability: str,
        requester_id: str
    ) -> bool:
        """Check if invocation is allowed by policy."""
        # TODO: Implement policy checking
        return True

    # Future: Integration with SOC message bus
    async def publish_to_soc(self, topic: str, message: Dict[str, Any]):
        """Publish message to SOC message bus."""
        # TODO: Implement SOC message bus integration
        logger.debug(f"Publishing to SOC topic {topic}: {message}")

    async def subscribe_from_soc(self, topic: str):
        """Subscribe to messages from SOC message bus."""
        # TODO: Implement SOC message bus subscription
        logger.debug(f"Subscribing to SOC topic {topic}")
        # This would be an async generator yielding messages
        while True:
            await asyncio.sleep(1)
            yield None
