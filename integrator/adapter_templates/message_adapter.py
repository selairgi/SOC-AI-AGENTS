"""
Message Queue adapter for pub/sub based agents.
"""

import asyncio
import json
from typing import Dict, Any, Optional
import logging

from .base_adapter import BaseAdapter
from ..models import AgentManifest, AdapterConfig

logger = logging.getLogger(__name__)


class MessageQueueAdapter(BaseAdapter):
    """Adapter for agents using message queues (RabbitMQ, Kafka, Redis, etc.)."""

    def __init__(self, manifest: AgentManifest, config: Optional[AdapterConfig] = None):
        super().__init__(manifest, config)

        self.input_topic = self._get_topic('input')
        self.output_topic = self._get_topic('output')

        # Message broker client (will be initialized based on type)
        self.broker_client = None
        self.broker_type = self._detect_broker_type()

        logger.info(f"Message adapter initialized: {self.input_topic} -> {self.output_topic}")

    def _get_topic(self, topic_type: str) -> str:
        """Get topic name from manifest."""
        if self.manifest.message_topics and topic_type in self.manifest.message_topics:
            return self.manifest.message_topics[topic_type]
        else:
            # Generate default topic names
            return f"{self.manifest.agent_id}.{topic_type}"

    def _detect_broker_type(self) -> str:
        """Detect message broker type from dependencies."""
        deps = ' '.join(self.manifest.dependencies).lower()

        if 'pika' in deps or 'rabbitmq' in deps:
            return 'rabbitmq'
        elif 'kafka' in deps:
            return 'kafka'
        elif 'redis' in deps:
            return 'redis'
        else:
            return 'redis'  # Default to Redis as it's most common

    async def _init_broker(self):
        """Initialize broker connection."""
        if self.broker_client:
            return

        if self.broker_type == 'redis':
            await self._init_redis()
        elif self.broker_type == 'rabbitmq':
            await self._init_rabbitmq()
        elif self.broker_type == 'kafka':
            await self._init_kafka()

    async def _init_redis(self):
        """Initialize Redis pub/sub."""
        try:
            import aioredis
            self.broker_client = await aioredis.create_redis_pool('redis://localhost')
            logger.info("Connected to Redis")
        except ImportError:
            logger.warning("aioredis not installed, using mock broker")
            self.broker_client = MockBroker()
        except Exception as e:
            logger.warning(f"Could not connect to Redis: {e}, using mock")
            self.broker_client = MockBroker()

    async def _init_rabbitmq(self):
        """Initialize RabbitMQ connection."""
        logger.warning("RabbitMQ not yet implemented, using mock broker")
        self.broker_client = MockBroker()

    async def _init_kafka(self):
        """Initialize Kafka connection."""
        logger.warning("Kafka not yet implemented, using mock broker")
        self.broker_client = MockBroker()

    async def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke agent via message queue.

        Args:
            input_data: Input data

        Returns:
            Response from agent
        """
        await self._init_broker()

        # Transform input
        agent_input = self._transform_input(input_data)

        # Generate correlation ID for request/response matching
        correlation_id = f"{self.manifest.agent_id}-{asyncio.get_event_loop().time()}"

        # Add correlation ID to message
        message = {
            'correlation_id': correlation_id,
            'data': agent_input
        }

        # Publish to input topic
        await self._publish(self.input_topic, message)
        logger.debug(f"Published message to {self.input_topic}")

        # Wait for response on output topic
        response = await self._wait_for_response(correlation_id, timeout=self.config.timeout)

        # Transform output
        return self._transform_output(response)

    async def _publish(self, topic: str, message: Dict[str, Any]):
        """Publish message to topic."""
        if hasattr(self.broker_client, 'publish'):
            await self.broker_client.publish(topic, json.dumps(message))
        else:
            logger.warning(f"Broker client has no publish method")

    async def _wait_for_response(self, correlation_id: str, timeout: float) -> Dict[str, Any]:
        """Wait for response with matching correlation ID."""
        start_time = asyncio.get_event_loop().time()

        # Subscribe to output topic
        if hasattr(self.broker_client, 'subscribe'):
            async for message in self.broker_client.subscribe(self.output_topic):
                try:
                    data = json.loads(message)
                    if data.get('correlation_id') == correlation_id:
                        return data.get('data', {})
                except json.JSONDecodeError:
                    continue

                # Check timeout
                if asyncio.get_event_loop().time() - start_time > timeout:
                    raise TimeoutError(f"No response received within {timeout}s")
        else:
            # Mock response
            await asyncio.sleep(0.1)
            return {"status": "success", "message": "Mock response from message queue"}

    async def health_check(self) -> bool:
        """Check if message broker is reachable."""
        try:
            await self._init_broker()
            return self.broker_client is not None
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def close(self):
        """Close broker connection."""
        if self.broker_client:
            if hasattr(self.broker_client, 'close'):
                await self.broker_client.close()


class MockBroker:
    """Mock broker for testing when real broker is not available."""

    def __init__(self):
        self.messages = {}

    async def publish(self, topic: str, message: str):
        """Mock publish."""
        logger.debug(f"Mock publish to {topic}: {message}")
        if topic not in self.messages:
            self.messages[topic] = []
        self.messages[topic].append(message)

    async def subscribe(self, topic: str):
        """Mock subscribe."""
        logger.debug(f"Mock subscribe to {topic}")
        # Yield no messages (agent will timeout and use fallback)
        await asyncio.sleep(0.1)
        return
        yield  # Make this an async generator
