# Universal Agent Integrator Architecture

## Overview
A system that automatically discovers agents in any repository, generates adapters, and integrates them into the SOC-AI-AGENTS ecosystem.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        WEB UI & API LAYER                           │
│  - Agent Catalog View     - Manifest Review & Editing               │
│  - Test Results Dashboard - Approval Workflow                       │
│  - Monitoring & Metrics   - Integration Management                  │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR / BROKER                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │  Agent Registry  │  │  Message Router  │  │  Policy Engine  │  │
│  │  (Capabilities)  │  │  (Pub/Sub)       │  │  (Auth/Safety)  │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘  │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      INTEGRATOR CORE                                │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐ │
│  │ Repo Scanner  │→ │ Agent Discover│→ │  Manifest Generator    │ │
│  │ (Clone/Scan)  │  │ (Heuristics)  │  │  (LLM + Analysis)      │ │
│  └───────────────┘  └───────────────┘  └────────────┬───────────┘ │
│                                                       │              │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────▼───────────┐ │
│  │ Adapter Tests │← │ Adapter Gen   │← │  Template Selector    │ │
│  │ (Sandbox)     │  │ (Wrappers)    │  │  (REST/Msg/CLI)       │ │
│  └───────────────┘  └───────────────┘  └───────────────────────┘ │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EXTERNAL AGENT ADAPTERS                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ REST Adapter │  │ Message Bus  │  │ CLI/Process Adapter      │ │
│  │ (OpenAPI)    │  │ Adapter      │  │ (Subprocess/Docker)      │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│              EXTERNAL AGENT SYSTEMS (Target Repos)                  │
│  - GitHub: 500-AI-Agents-Projects                                   │
│  - Any multi-agent systems                                          │
│  - Custom agent implementations                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Repository Scanner
**File:** `integrator/repo_scanner.py`

**Responsibilities:**
- Clone target repositories
- Detect languages (Python, JavaScript, Go, etc.)
- Find Dockerfiles, package.json, requirements.txt
- Parse README files
- Detect OpenAPI/Swagger specs
- Extract entrypoints and main files
- Identify testing frameworks

**Key Functions:**
```python
def scan_repository(repo_url: str) -> RepoMetadata
def detect_languages(repo_path: str) -> Dict[str, float]
def find_entrypoints(repo_path: str) -> List[EntryPoint]
def extract_dependencies(repo_path: str) -> Dependencies
```

### 2. Agent Discovery Engine
**File:** `integrator/agent_discovery.py`

**Responsibilities:**
- Identify potential agents using heuristics
- Detect agent patterns (files named agent.py, worker.py, main.py)
- Find message queue usage (RabbitMQ, Kafka, Redis)
- Detect API endpoints (FastAPI, Flask, Express)
- Identify agent frameworks (LangGraph, CrewAI, AutoGen)

**Heuristics:**
- Files with "agent" in name
- Classes inheriting from agent frameworks
- Message handler decorators
- API route definitions
- Docker ENTRYPOINT/CMD patterns

**Key Functions:**
```python
def discover_agents(repo_metadata: RepoMetadata) -> List[PotentialAgent]
def analyze_code_patterns(file_path: str) -> CodePattern
def detect_agent_framework(repo_path: str) -> Optional[str]
```

### 3. Manifest Generator
**File:** `integrator/manifest_generator.py`

**Responsibilities:**
- Generate agent manifests using LLM + static analysis
- Extract capabilities from code and docs
- Infer input/output schemas
- Determine security impact level
- Propose adapter type

**Agent Manifest Schema:**
```python
@dataclass
class AgentManifest:
    agent_id: str
    name: str
    description: str
    repo_url: str
    framework: str  # "custom", "langchain", "autogen", etc.
    language: str

    # Capabilities
    capabilities: List[str]  # ["analyze_logs", "generate_reports"]
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]

    # Interface
    interface_type: str  # "rest", "message_queue", "cli", "function"
    endpoint: Optional[str]
    message_topics: Optional[List[str]]
    command: Optional[str]

    # Security
    security_level: str  # "low", "medium", "high", "critical"
    impact_level: str  # "read_only", "write", "execute", "admin"
    required_permissions: List[str]

    # Deployment
    docker_image: Optional[str]
    env_vars: Dict[str, str]
    dependencies: List[str]

    # Monitoring
    health_check: Optional[str]
    metrics_endpoint: Optional[str]
```

### 4. Adapter Templates
**File:** `integrator/adapter_templates/`

**Template Types:**

#### a. REST Adapter
For agents exposing HTTP APIs:
```python
class RESTAdapter(BaseAdapter):
    def __init__(self, manifest: AgentManifest):
        self.base_url = manifest.endpoint
        self.auth = self._setup_auth(manifest)

    async def invoke(self, input_data: Dict) -> Dict:
        # Transform input to agent's schema
        agent_input = self._transform_input(input_data)

        # Call agent API with retry + circuit breaker
        response = await self._call_with_retry(agent_input)

        # Transform output to standard schema
        return self._transform_output(response)

    def _transform_input(self, data: Dict) -> Dict:
        # Schema transformation logic
        pass
```

#### b. Message Queue Adapter
For agents using pub/sub messaging:
```python
class MessageQueueAdapter(BaseAdapter):
    def __init__(self, manifest: AgentManifest):
        self.topics = manifest.message_topics
        self.broker = self._connect_broker(manifest)

    async def invoke(self, input_data: Dict) -> Dict:
        # Publish to agent's input topic
        await self.broker.publish(
            topic=self.topics['input'],
            message=self._transform_input(input_data)
        )

        # Wait for response on output topic
        response = await self.broker.subscribe(
            topic=self.topics['output'],
            timeout=30.0
        )

        return self._transform_output(response)
```

#### c. CLI/Process Adapter
For agents that run as CLI tools:
```python
class CLIAdapter(BaseAdapter):
    def __init__(self, manifest: AgentManifest):
        self.command = manifest.command
        self.docker_image = manifest.docker_image

    async def invoke(self, input_data: Dict) -> Dict:
        # Prepare command with input
        cmd = self._build_command(input_data)

        # Run in Docker sandbox
        result = await self._run_in_sandbox(cmd)

        # Parse output
        return self._parse_output(result)
```

### 5. Adapter Generator
**File:** `integrator/adapter_generator.py`

**Responsibilities:**
- Choose best-fit adapter template
- Generate adapter code from manifest
- Add schema transformation logic
- Inject authentication/authorization
- Add retry logic and circuit breakers
- Include safety checks

**Safety Checks:**
- Input validation against schema
- Output sanitization
- Rate limiting
- Timeout enforcement
- Resource limits

### 6. Sandbox Tester
**File:** `integrator/sandbox_tester.py`

**Responsibilities:**
- Test adapters in isolated environment
- Simulate various input scenarios
- Check expected outputs
- Verify safety constraints
- Measure performance
- Generate test reports

**Test Scenarios:**
```python
class SandboxTester:
    async def test_adapter(self, adapter: BaseAdapter) -> TestReport:
        results = []

        # Basic functionality test
        results.append(await self._test_basic_invocation(adapter))

        # Schema validation test
        results.append(await self._test_schema_compliance(adapter))

        # Error handling test
        results.append(await self._test_error_conditions(adapter))

        # Performance test
        results.append(await self._test_performance(adapter))

        # Safety test
        results.append(await self._test_safety_constraints(adapter))

        return TestReport(results)
```

### 7. Integration Broker/Orchestrator
**File:** `integrator/integration_broker.py`

**Responsibilities:**
- Maintain agent registry
- Route messages to appropriate agents
- Handle agent discovery and health checks
- Enforce policies and permissions
- Track telemetry and metrics

**Key Features:**
```python
class IntegrationBroker:
    def __init__(self):
        self.registry: Dict[str, RegisteredAgent] = {}
        self.message_bus: MessageBus = MessageBus()
        self.policy_engine: PolicyEngine = PolicyEngine()

    async def register_agent(self, manifest: AgentManifest, adapter: BaseAdapter):
        """Register external agent with capabilities"""
        pass

    async def invoke_agent(self, agent_id: str, capability: str, input_data: Dict) -> Dict:
        """Invoke agent capability with policy enforcement"""
        # 1. Policy check
        if not await self.policy_engine.check_permission(agent_id, capability):
            raise PermissionDeniedError()

        # 2. Get adapter
        agent = self.registry[agent_id]

        # 3. Invoke with monitoring
        result = await self._monitored_invoke(agent, capability, input_data)

        # 4. Audit log
        await self._log_invocation(agent_id, capability, result)

        return result

    async def discover_agent(self, capability: str) -> List[str]:
        """Find agents that can handle a capability"""
        return [
            agent_id for agent_id, agent in self.registry.items()
            if capability in agent.manifest.capabilities
        ]
```

### 8. Web UI for Review & Management
**File:** `integrator/web_ui.py`

**Pages:**

1. **Agent Catalog** - Browse discovered agents
2. **Manifest Review** - Edit and approve manifests
3. **Adapter Configuration** - Configure adapter settings
4. **Test Results** - View sandbox test outcomes
5. **Integration Dashboard** - Monitor active integrations
6. **Metrics & Telemetry** - Track usage, costs, errors

## Integration Workflow

### Phase 1: Discovery
1. User provides repo URL or uploads repo catalog
2. System clones and scans repository
3. Agent discovery runs heuristics
4. Potential agents listed in UI

### Phase 2: Manifest Generation
1. For each potential agent:
   - LLM analyzes code + README + tests
   - Static analysis extracts schemas
   - System proposes manifest
2. Human reviews and edits manifest
3. Operator approves or rejects

### Phase 3: Adapter Generation
1. System selects adapter template
2. Generates adapter code with:
   - Schema transformations
   - Auth/auth logic
   - Safety checks
   - Retry/circuit breaker
3. Saves adapter to `adapters/{agent_id}.py`

### Phase 4: Testing
1. Load adapter in sandbox
2. Run test scenarios
3. Display results in UI:
   - Test logs
   - Sample interactions
   - Performance metrics
   - Safety check results
4. Operator reviews and approves

### Phase 5: Deployment
1. Register adapter with broker
2. Configure policies and permissions
3. Enable agent in orchestrator
4. Monitor health and metrics

### Phase 6: Monitoring
1. Collect telemetries:
   - Request counts
   - Response times
   - Error rates
   - Token usage/costs
2. Track false positives
3. Continuous auditing
4. Alert on anomalies

## Integration with SOC-AI-AGENTS

### Message Bus Integration
External agents can publish/subscribe to SOC message bus:

```python
# External agent publishes security alert
await integration_broker.publish_to_soc(
    topic="security.alerts",
    alert=Alert(...)
)

# External agent subscribes to SOC events
async for playbook in integration_broker.subscribe_from_soc("remediation.playbooks"):
    await external_agent.handle_playbook(playbook)
```

### Capability-Based Discovery
SOC Analyst can discover external agents by capability:

```python
# SOC Analyst needs malware analysis
analysts_agents = await integration_broker.discover_agent("malware_analysis")

for agent_id in analysts_agents:
    result = await integration_broker.invoke_agent(
        agent_id=agent_id,
        capability="malware_analysis",
        input_data={"file_hash": "abc123", "file_url": "https://..."}
    )
```

### Security Guardrails
All external agent invocations go through:
1. **Policy Engine** - Permissions and approval workflows
2. **Input Sanitization** - Prevent injection attacks
3. **Rate Limiting** - Prevent abuse
4. **Timeout Enforcement** - Prevent hanging
5. **Audit Logging** - Complete trace
6. **Cost Tracking** - Monitor API costs

## File Structure

```
integrator/
├── __init__.py
├── models.py                 # Data models for manifests, adapters, etc.
├── repo_scanner.py           # Clone and scan repos
├── agent_discovery.py        # Discover agents using heuristics
├── manifest_generator.py     # Generate manifests with LLM
├── adapter_generator.py      # Generate adapter code
├── sandbox_tester.py         # Test adapters in sandbox
├── integration_broker.py     # Orchestrate and route messages
├── policy_engine.py          # Enforce policies and permissions
├── monitoring.py             # Collect metrics and telemetry
├── web_ui.py                 # Flask app for UI
├── adapter_templates/
│   ├── base_adapter.py       # Base adapter interface
│   ├── rest_adapter.py       # REST API template
│   ├── message_adapter.py    # Message queue template
│   └── cli_adapter.py        # CLI/process template
├── adapters/                 # Generated adapters stored here
│   └── {agent_id}.py
├── templates/                # HTML templates for web UI
│   ├── catalog.html
│   ├── manifest_review.html
│   ├── test_results.html
│   └── dashboard.html
└── tests/
    ├── test_scanner.py
    ├── test_discovery.py
    └── test_adapters.py
```

## Example: Integrating Agent from 500-AI-Agents-Projects

### Step 1: Scan Repository
```bash
python -m integrator.repo_scanner https://github.com/ashishpatel26/500-AI-Agents-Projects
```

Output:
```
Found 47 potential agents:
1. Medical Diagnosis Agent (Python, Flask API)
2. Code Review Agent (Python, LangChain)
3. Data Analysis Agent (Python, Pandas + GPT)
...
```

### Step 2: Review Generated Manifest
```json
{
  "agent_id": "medical-diagnosis-agent",
  "name": "Medical Diagnosis Agent",
  "description": "Analyzes patient symptoms and provides diagnostic suggestions",
  "capabilities": ["symptom_analysis", "diagnosis_suggestion", "treatment_recommendation"],
  "interface_type": "rest",
  "endpoint": "http://localhost:8000/diagnose",
  "security_level": "critical",
  "impact_level": "write"
}
```

### Step 3: Adapter Generated
```python
# adapters/medical-diagnosis-agent.py
class MedicalDiagnosisAdapter(RESTAdapter):
    async def invoke(self, input_data: Dict) -> Dict:
        # Transform SOC alert to agent input
        agent_input = {
            "symptoms": input_data.get("evidence", {}).get("symptoms", []),
            "patient_history": input_data.get("metadata", {})
        }

        # Call agent API
        response = await self.client.post(
            f"{self.base_url}/diagnose",
            json=agent_input,
            timeout=30.0
        )

        # Transform response to standard format
        return {
            "diagnosis": response.json()["diagnosis"],
            "confidence": response.json()["confidence"],
            "recommendations": response.json()["treatment_plan"]
        }
```

### Step 4: Test in Sandbox
```python
# Test results
✅ Basic invocation: PASSED
✅ Schema validation: PASSED
⚠️  Error handling: WARNING - No 404 handler
✅ Performance: PASSED (avg 250ms)
✅ Safety checks: PASSED
```

### Step 5: Register with Broker
```python
await integration_broker.register_agent(
    manifest=medical_manifest,
    adapter=MedicalDiagnosisAdapter(medical_manifest)
)
```

### Step 6: Use in SOC Workflow
```python
# SOC Analyst detects health-related alert
alert = Alert(
    title="Suspicious Medical Record Access",
    threat_type=ThreatType.PRIVACY_VIOLATION,
    evidence={"symptoms": ["fever", "cough"]}
)

# Discover agents that can help
agents = await integration_broker.discover_agent("symptom_analysis")

# Invoke medical diagnosis agent for context
result = await integration_broker.invoke_agent(
    agent_id="medical-diagnosis-agent",
    capability="symptom_analysis",
    input_data=alert.evidence
)

# Use result in playbook
playbook = Playbook(
    action="investigate",
    target="medical_records_system",
    justification=f"Diagnosis context: {result['diagnosis']}"
)
```

## Next Steps

1. Implement core components
2. Create adapter templates
3. Build web UI
4. Test with sample repos
5. Integrate with SOC system
6. Deploy and monitor
