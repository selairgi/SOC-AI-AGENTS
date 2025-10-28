# Universal Agent Integrator

A system that automatically discovers agents in any repository, generates adapters, and integrates them into the SOC-AI-AGENTS ecosystem.

## Overview

The Universal Agent Integrator enables your SOC-AI-AGENTS to work alongside **any other agent system** by:

1. **Automatically scanning** repositories (like the [500-AI-Agents-Projects](https://github.com/ashishpatel26/500-AI-Agents-Projects))
2. **Discovering agents** using intelligent heuristics and code analysis
3. **Generating manifests** with LLM-assisted capability extraction
4. **Creating adapters** that handle schema transformations, auth, and safety checks
5. **Registering agents** in a central broker for capability-based discovery
6. **Orchestrating interactions** between SOC agents and external agents

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTEGRATION BROKER                           │
│  - Agent Registry  - Message Router  - Policy Engine           │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐
  │   REST   │    │ Message  │    │   CLI    │
  │ Adapter  │    │  Queue   │    │ Adapter  │
  └────┬─────┘    └────┬─────┘    └────┬─────┘
       │               │               │
       ▼               ▼               ▼
┌─────────────────────────────────────────────┐
│          EXTERNAL AGENT SYSTEMS             │
│  - 500 AI Agents   - Custom Agents         │
└─────────────────────────────────────────────┘
```

## Features

### 1. Repository Scanner
- Clones and analyzes repositories
- Detects languages (Python, JavaScript, Go, Java, etc.)
- Finds Dockerfiles, package managers, and dependencies
- Locates entry points and API specifications

### 2. Agent Discovery Engine
- Uses heuristics to find potential agents
- Detects agent frameworks (LangChain, AutoGen, CrewAI, etc.)
- Identifies interface types (REST, Message Queue, CLI)
- Assigns confidence scores

### 3. Manifest Generator
- Extracts agent capabilities using LLM + static analysis
- Generates comprehensive agent manifests
- Infers input/output schemas
- Determines security and impact levels

### 4. Adapter System
- **REST Adapter**: For HTTP APIs with connection pooling
- **Message Queue Adapter**: For pub/sub systems (Redis, RabbitMQ, Kafka)
- **CLI Adapter**: For command-line tools and Docker containers
- Built-in retry logic, circuit breakers, and timeout handling

### 5. Integration Broker
- Central registry for all external agents
- Capability-based agent discovery
- Health monitoring and metrics tracking
- Policy enforcement (coming soon)

## Installation

### Prerequisites
```bash
python --version  # 3.8 or higher
pip --version
```

### Install Dependencies
```bash
cd "C:\Users\LENOVO\Desktop\SOC ai agents"
pip install aiohttp aioredis  # For adapters
```

### Optional: OpenAI API Key
For enhanced manifest generation with LLM analysis:
```bash
export OPENAI_API_KEY=sk-your-key-here
```

## Quick Start

### Example 1: Scan a Repository

```python
from integrator.repo_scanner import RepositoryScanner

scanner = RepositoryScanner()
metadata = scanner.scan_repository("https://github.com/ashishpatel26/500-AI-Agents-Projects")

print(f"Languages: {metadata.languages}")
print(f"Entry points: {len(metadata.entrypoints)}")
```

### Example 2: Discover Agents

```python
from integrator.agent_discovery import AgentDiscoveryEngine

discovery = AgentDiscoveryEngine()
agents = discovery.discover_agents(metadata)

for agent in agents:
    print(f"{agent.name} - Confidence: {agent.confidence:.0%}")
```

### Example 3: Generate Manifest

```python
from integrator.manifest_generator import ManifestGenerator

generator = ManifestGenerator(openai_api_key="sk-...")
manifest = generator.generate_manifest(agents[0], metadata)

print(f"Capabilities: {manifest.capabilities}")
print(f"Interface: {manifest.interface_type}")
```

### Example 4: Register and Invoke

```python
import asyncio
from integrator.integration_broker import IntegrationBroker

async def main():
    broker = IntegrationBroker()
    await broker.start()

    # Register agent
    broker.register_agent(manifest)

    # Invoke agent
    result = await broker.invoke_agent(
        agent_id="malware-analyzer",
        capability="analyze_file",
        input_data={"file_hash": "abc123"}
    )

    print(f"Success: {result.success}")
    print(f"Output: {result.output_data}")

    await broker.stop()

asyncio.run(main())
```

## Complete Integration Workflow

Run the example integration script:

```bash
python example_integration.py
```

Choose from:
1. **Full integration workflow** - Scan repo → discover agents → integrate
2. **SOC integration demo** - See how SOC agents use external agents
3. **Both demos**

## CLI Tools

### Scan Repository
```bash
python -m integrator.repo_scanner https://github.com/user/repo
```

### Discover Agents
```bash
python -m integrator.agent_discovery https://github.com/user/repo
```

### Generate Manifests
```bash
export OPENAI_API_KEY=sk-your-key
python -m integrator.manifest_generator https://github.com/user/repo
```

## Use Cases

### 1. Malware Analysis
SOC Analyst detects suspicious file → discovers malware analysis agent → invokes external scanner → creates remediation playbook

```python
# SOC Analyst discovers available analyzers
analyzers = broker.discover_agents_by_capability("malware_analysis")

# Invoke external malware analyzer
result = await broker.invoke_agent(
    agent_id=analyzers[0],
    capability="malware_analysis",
    input_data={
        "file_hash": "abc123",
        "file_url": "https://suspicious.com/file.exe"
    }
)

# Use results in playbook
if result.output_data['is_malicious']:
    playbook = create_remediation_playbook(result.output_data)
```

### 2. Threat Intelligence Enrichment
Alert generated → query external threat intel agents → correlate findings → adjust severity

### 3. Automated Response
Security incident → discover response agents (firewall, SIEM, ticketing) → orchestrate multi-agent response

### 4. Log Analysis
Anomaly detected → send logs to external analysis agents → aggregate insights → generate report

## Integrating with SOC-AI-AGENTS

### Method 1: Direct Integration

```python
# In soc_analyst.py
from integrator.integration_broker import IntegrationBroker

class SOCAnalyst:
    def __init__(self):
        self.broker = IntegrationBroker()
        # ... existing code ...

    async def analyze_alert(self, alert: Alert):
        # Check if external agents can help
        agents = self.broker.discover_agents_by_capability("log_analysis")

        if agents:
            # Invoke external agent
            result = await self.broker.invoke_agent(
                agent_id=agents[0],
                capability="log_analysis",
                input_data=alert.evidence
            )

            # Use external analysis in playbook
            playbook = self._create_playbook_with_external_data(
                alert, result.output_data
            )
```

### Method 2: Message Bus Integration

```python
# External agents can publish to SOC message bus
await broker.publish_to_soc(
    topic="security.alerts",
    message={
        "type": "external_finding",
        "source": "threat-intel-agent",
        "severity": "high",
        "data": {...}
    }
)

# SOC agents can subscribe to external agent events
async for event in broker.subscribe_from_soc("external.events"):
    await soc_analyst.handle_external_event(event)
```

## Agent Manifest Schema

```python
{
  "agent_id": "malware-analyzer",
  "name": "Advanced Malware Analyzer",
  "description": "Analyzes files and URLs for malware",
  "capabilities": ["malware_analysis", "threat_detection"],

  "interface_type": "rest",  # or "message_queue", "cli"
  "endpoint": "http://localhost:8000/analyze",
  "port": 8000,

  "security_level": "high",  # low, medium, high, critical
  "impact_level": "read_only",  # read_only, write, execute, admin

  "input_schema": {
    "type": "object",
    "properties": {
      "file_hash": {"type": "string"},
      "file_url": {"type": "string"}
    }
  },

  "output_schema": {
    "type": "object",
    "properties": {
      "is_malicious": {"type": "boolean"},
      "threat_score": {"type": "number"},
      "indicators": {"type": "array"}
    }
  }
}
```

## Adapter Configuration

```python
from integrator.models import AdapterConfig

config = AdapterConfig(
    adapter_id="my-adapter",
    manifest=manifest,
    template_name="rest",

    # Reliability
    retry_enabled=True,
    max_retries=3,
    retry_delay=1.0,
    circuit_breaker_enabled=True,
    timeout=30.0,

    # Safety
    input_validation=True,
    output_sanitization=True,
    rate_limit=100,  # requests per minute
    cost_limit=0.10,  # max cost per request

    # Monitoring
    enable_logging=True,
    enable_metrics=True,
    enable_tracing=True
)
```

## Security Considerations

### Input Validation
All adapters validate input against schemas before invoking external agents.

### Output Sanitization
Sensitive fields (passwords, tokens, keys) are automatically redacted from outputs.

### Rate Limiting
Prevent abuse with configurable per-agent rate limits.

### Timeout Enforcement
All invocations have configurable timeouts to prevent hanging.

### Impact Levels
- **READ_ONLY**: Agent can only read/analyze data
- **WRITE**: Agent can modify data
- **EXECUTE**: Agent can execute commands
- **ADMIN**: Agent has elevated privileges

### Security Levels
- **LOW**: Public agents, no sensitive data
- **MEDIUM**: Internal agents, some sensitive data
- **HIGH**: Critical agents, requires authentication
- **CRITICAL**: High-privilege agents, requires approval

## Monitoring & Metrics

```python
# Get broker metrics
metrics = broker.get_metrics()
print(f"Total agents: {metrics['total_agents']}")
print(f"Success rate: {metrics['success_rate']}%")
print(f"Average latency: {metrics['average_latency']}s")

# Get agent-specific stats
agent_info = broker.get_agent_info("malware-analyzer")
print(f"Invocations: {agent_info['total_invocations']}")
print(f"Errors: {agent_info['total_errors']}")
print(f"Health: {agent_info['is_healthy']}")
```

## Advanced Features

### Custom Adapters
Create custom adapters by extending `BaseAdapter`:

```python
from integrator.adapter_templates.base_adapter import BaseAdapter

class MyCustomAdapter(BaseAdapter):
    async def invoke(self, input_data: Dict) -> Dict:
        # Custom invocation logic
        return {"result": "success"}

    async def health_check(self) -> bool:
        # Custom health check
        return True
```

### Schema Transformation
Map between SOC schema and external agent schema:

```python
config = AdapterConfig(
    input_transform={
        "alert_id": "id",
        "severity": "priority",
        "evidence": "data"
    },
    output_transform={
        "result": "analysis_result",
        "confidence": "score"
    }
)
```

### Policy Engine (Coming Soon)
Define policies for agent invocation:

```python
policy = PolicyRule(
    rule_id="critical-only",
    agent_pattern="malware-.*",
    capability_pattern=".*",
    allowed=True,
    requires_approval=True,
    max_cost_per_request=1.0
)
```

## Troubleshooting

### Issue: Agents not discovered
**Solution**: Check that files match heuristics (contain "agent", "bot", etc. in name or use known frameworks)

### Issue: Manifest generation fails
**Solution**: Set OPENAI_API_KEY or the system will use heuristic-based generation

### Issue: Adapter invocation fails
**Solution**: Check that external agent is running and endpoint/port are correct

### Issue: Health checks failing
**Solution**: Ensure external agents expose health endpoints or respond to basic queries

## Future Enhancements

- [ ] Web UI for manifest review and approval
- [ ] Sandbox testing environment
- [ ] Policy engine with approval workflows
- [ ] Support for gRPC and WebSocket adapters
- [ ] Automatic adapter generation from OpenAPI specs
- [ ] Integration with more message brokers (NATS, ZeroMQ)
- [ ] Cost tracking and budget limits
- [ ] A/B testing for multiple agents with same capability
- [ ] Agent versioning and rollback

## Project Structure

```
integrator/
├── __init__.py
├── models.py                      # Data models
├── repo_scanner.py                # Repository scanning
├── agent_discovery.py             # Agent discovery engine
├── manifest_generator.py          # Manifest generation with LLM
├── integration_broker.py          # Central orchestrator
├── adapter_templates/
│   ├── base_adapter.py           # Base adapter interface
│   ├── rest_adapter.py           # REST API adapter
│   ├── message_adapter.py        # Message queue adapter
│   └── cli_adapter.py            # CLI/process adapter
├── adapters/                      # Generated adapters
└── templates/                     # Web UI templates (future)

example_integration.py             # Complete demo script
integrator_architecture.md         # Architecture documentation
INTEGRATOR_README.md              # This file
```

## Contributing

To add support for new agent frameworks:

1. Add framework to `AgentFramework` enum in `models.py`
2. Add detection patterns to `FRAMEWORK_PATTERNS` in `agent_discovery.py`
3. Test with example repositories

To add new adapter types:

1. Create new adapter class extending `BaseAdapter`
2. Implement `invoke()` and `health_check()` methods
3. Register in `integration_broker.py`

## Resources

- **SOC-AI-AGENTS**: See main README.md for SOC system details
- **500 AI Agents**: https://github.com/ashishpatel26/500-AI-Agents-Projects
- **LangChain**: https://python.langchain.com/
- **AutoGen**: https://microsoft.github.io/autogen/
- **CrewAI**: https://www.crewai.io/

## License

Same as SOC-AI-AGENTS parent project.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review example_integration.py for usage examples
3. Check logs for detailed error messages
4. Ensure all dependencies are installed

---

**Built with the Universal Agent Integrator, your SOC-AI-AGENTS can now collaborate with any agent system in the ecosystem.**
