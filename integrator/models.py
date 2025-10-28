"""
Data models for Universal Agent Integrator.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime


class InterfaceType(Enum):
    """Agent interface types."""
    REST = "rest"
    MESSAGE_QUEUE = "message_queue"
    CLI = "cli"
    FUNCTION = "function"
    GRPC = "grpc"
    WEBSOCKET = "websocket"


class SecurityLevel(Enum):
    """Security impact levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImpactLevel(Enum):
    """Agent operation impact levels."""
    READ_ONLY = "read_only"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"


class AgentFramework(Enum):
    """Known agent frameworks."""
    CUSTOM = "custom"
    LANGCHAIN = "langchain"
    LANGGRAPH = "langgraph"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    HAYSTACK = "haystack"
    RASA = "rasa"
    BOTPRESS = "botpress"


class AdapterStatus(Enum):
    """Adapter lifecycle status."""
    DISCOVERED = "discovered"
    MANIFEST_GENERATED = "manifest_generated"
    REVIEWED = "reviewed"
    ADAPTER_GENERATED = "adapter_generated"
    TESTING = "testing"
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    RETIRED = "retired"


@dataclass
class RepoMetadata:
    """Metadata extracted from repository scan."""
    repo_url: str
    repo_path: str
    languages: Dict[str, float]  # Language -> percentage
    has_dockerfile: bool
    has_docker_compose: bool
    package_files: List[str]  # requirements.txt, package.json, etc.
    entrypoints: List[str]
    readme_path: Optional[str] = None
    openapi_specs: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    scanned_at: datetime = field(default_factory=datetime.now)


@dataclass
class EntryPoint:
    """Detected entry point in code."""
    file_path: str
    entry_type: str  # "main", "api", "worker", "agent"
    line_number: int
    code_snippet: str


@dataclass
class CodePattern:
    """Detected code pattern indicating agent functionality."""
    pattern_type: str  # "message_handler", "api_route", "agent_class"
    file_path: str
    line_number: int
    confidence: float  # 0.0 to 1.0
    evidence: str  # Code snippet or description


@dataclass
class PotentialAgent:
    """Discovered potential agent in repository."""
    agent_id: str
    name: str
    file_path: str
    confidence: float  # 0.0 to 1.0
    patterns: List[CodePattern]
    framework: Optional[AgentFramework] = None
    interface_hints: List[InterfaceType] = field(default_factory=list)
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentManifest:
    """Complete agent manifest for integration."""
    agent_id: str
    name: str
    description: str
    repo_url: str
    file_path: str

    # Framework and language
    framework: AgentFramework
    language: str
    version: str = "1.0.0"

    # Capabilities
    capabilities: List[str] = field(default_factory=list)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)

    # Interface configuration
    interface_type: InterfaceType = InterfaceType.REST
    endpoint: Optional[str] = None
    message_topics: Optional[Dict[str, str]] = None  # {"input": "topic1", "output": "topic2"}
    command: Optional[str] = None
    port: Optional[int] = None

    # Security
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    impact_level: ImpactLevel = ImpactLevel.READ_ONLY
    required_permissions: List[str] = field(default_factory=list)
    auth_type: Optional[str] = None  # "api_key", "oauth", "jwt", "none"

    # Deployment
    docker_image: Optional[str] = None
    docker_compose_file: Optional[str] = None
    env_vars: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    install_command: Optional[str] = None
    start_command: Optional[str] = None

    # Monitoring
    health_check: Optional[str] = None
    metrics_endpoint: Optional[str] = None
    log_file: Optional[str] = None

    # Metadata
    tags: List[str] = field(default_factory=list)
    documentation_url: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None

    # Status
    status: AdapterStatus = AdapterStatus.DISCOVERED
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    reviewed_by: Optional[str] = None
    approved_by: Optional[str] = None


@dataclass
class AdapterConfig:
    """Configuration for generated adapter."""
    adapter_id: str
    manifest: AgentManifest
    template_name: str  # "rest", "message_queue", "cli"

    # Transformation rules
    input_transform: Dict[str, str] = field(default_factory=dict)
    output_transform: Dict[str, str] = field(default_factory=dict)

    # Reliability settings
    retry_enabled: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5
    timeout: float = 30.0

    # Safety settings
    input_validation: bool = True
    output_sanitization: bool = True
    rate_limit: Optional[int] = None  # requests per minute
    cost_limit: Optional[float] = None  # max cost per request

    # Monitoring
    enable_logging: bool = True
    enable_metrics: bool = True
    enable_tracing: bool = True


@dataclass
class TestScenario:
    """Test scenario for adapter validation."""
    scenario_id: str
    name: str
    description: str
    input_data: Dict[str, Any]
    expected_output: Optional[Dict[str, Any]] = None
    expected_error: Optional[str] = None
    timeout: float = 30.0


@dataclass
class TestResult:
    """Result of adapter test."""
    scenario_id: str
    passed: bool
    execution_time: float
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    logs: List[str] = field(default_factory=list)


@dataclass
class TestReport:
    """Complete test report for adapter."""
    adapter_id: str
    test_results: List[TestResult]
    total_tests: int
    passed_tests: int
    failed_tests: int
    average_execution_time: float
    tested_at: datetime = field(default_factory=datetime.now)

    @property
    def success_rate(self) -> float:
        """Calculate test success rate."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100


@dataclass
class RegisteredAgent:
    """Agent registered in the integration broker."""
    manifest: AgentManifest
    adapter_config: AdapterConfig
    adapter_instance: Any  # The actual adapter object

    # Runtime state
    is_healthy: bool = True
    last_health_check: Optional[datetime] = None
    total_invocations: int = 0
    total_errors: int = 0
    total_cost: float = 0.0
    average_latency: float = 0.0

    # Telemetry
    registered_at: datetime = field(default_factory=datetime.now)
    last_invoked_at: Optional[datetime] = None


@dataclass
class InvocationRequest:
    """Request to invoke an external agent."""
    agent_id: str
    capability: str
    input_data: Dict[str, Any]
    requester_id: str
    session_id: Optional[str] = None
    timeout: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvocationResult:
    """Result of agent invocation."""
    request_id: str
    agent_id: str
    capability: str
    success: bool
    output_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    cost: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PolicyRule:
    """Policy rule for agent invocation."""
    rule_id: str
    name: str
    description: str
    agent_pattern: str  # Regex pattern for agent_id
    capability_pattern: str  # Regex pattern for capability
    requester_pattern: str  # Regex pattern for requester_id

    # Conditions
    allowed: bool = True
    requires_approval: bool = False
    max_cost_per_request: Optional[float] = None
    max_requests_per_minute: Optional[int] = None
    allowed_time_windows: List[Dict[str, str]] = field(default_factory=list)

    # Metadata
    priority: int = 0
    enabled: bool = True


@dataclass
class IntegrationMetrics:
    """Metrics for integration monitoring."""
    total_agents: int = 0
    healthy_agents: int = 0
    total_invocations: int = 0
    successful_invocations: int = 0
    failed_invocations: int = 0
    total_cost: float = 0.0
    average_latency: float = 0.0

    # Per-agent metrics
    agent_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Time-based
    start_time: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
