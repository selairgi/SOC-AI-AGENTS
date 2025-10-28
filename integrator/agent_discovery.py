"""
Agent Discovery Engine - Uses heuristics to discover agents in repositories.
"""

import re
import ast
from pathlib import Path
from typing import List, Optional
import logging

from .models import (
    RepoMetadata, PotentialAgent, CodePattern, AgentFramework, InterfaceType
)

logger = logging.getLogger(__name__)


class AgentDiscoveryEngine:
    """Discovers potential agents in scanned repositories using heuristics."""

    # Keywords that suggest agent functionality
    AGENT_KEYWORDS = [
        'agent', 'bot', 'assistant', 'worker', 'executor', 'handler',
        'processor', 'analyzer', 'monitor', 'automation', 'ai', 'llm', 'gpt'
    ]

    # Framework-specific patterns
    FRAMEWORK_PATTERNS = {
        AgentFramework.LANGCHAIN: [
            r'from langchain', r'import langchain', r'LangChain',
            r'class.*\(.*Agent.*\)', r'AgentExecutor'
        ],
        AgentFramework.LANGGRAPH: [
            r'from langgraph', r'import langgraph', r'StateGraph'
        ],
        AgentFramework.AUTOGEN: [
            r'from autogen', r'import autogen', r'AssistantAgent', r'UserProxyAgent'
        ],
        AgentFramework.CREWAI: [
            r'from crewai', r'import crewai', r'Agent', r'Crew', r'Task'
        ],
        AgentFramework.HAYSTACK: [
            r'from haystack', r'import haystack', r'Pipeline'
        ],
        AgentFramework.RASA: [
            r'from rasa', r'import rasa', r'Action'
        ]
    }

    # Interface type patterns
    INTERFACE_PATTERNS = {
        InterfaceType.REST: [
            r'@app\.route', r'@router\.', r'FastAPI', r'Flask',
            r'app\.get', r'app\.post', r'@api\.route'
        ],
        InterfaceType.MESSAGE_QUEUE: [
            r'pika\.', r'kombu\.', r'kafka\.', r'redis\.pubsub',
            r'@subscribe', r'consumer\.', r'producer\.'
        ],
        InterfaceType.CLI: [
            r'argparse\.', r'click\.', r'typer\.', r'if __name__ == ["\']__main__["\']'
        ],
        InterfaceType.GRPC: [
            r'grpc\.', r'_pb2\.', r'servicer'
        ],
        InterfaceType.WEBSOCKET: [
            r'websocket', r'socketio', r'ws\.'
        ]
    }

    def __init__(self):
        pass

    def discover_agents(self, repo_metadata: RepoMetadata) -> List[PotentialAgent]:
        """
        Discover potential agents in repository.

        Args:
            repo_metadata: Metadata from repository scan

        Returns:
            List of discovered potential agents
        """
        logger.info(f"Discovering agents in {repo_metadata.repo_path}")
        repo_path = Path(repo_metadata.repo_path)

        potential_agents = []

        # Search entry points first
        for entrypoint in repo_metadata.entrypoints:
            file_path = repo_path / entrypoint
            agents = self._analyze_file(file_path, repo_path)
            potential_agents.extend(agents)

        # Search for files with agent keywords
        for file_path in self._find_agent_files(repo_path):
            if str(file_path.relative_to(repo_path)) not in repo_metadata.entrypoints:
                agents = self._analyze_file(file_path, repo_path)
                potential_agents.extend(agents)

        # Deduplicate by agent_id
        seen_ids = set()
        unique_agents = []
        for agent in potential_agents:
            if agent.agent_id not in seen_ids:
                seen_ids.add(agent.agent_id)
                unique_agents.append(agent)

        logger.info(f"Discovered {len(unique_agents)} potential agents")
        return unique_agents

    def _find_agent_files(self, repo_path: Path) -> List[Path]:
        """Find files that likely contain agents."""
        agent_files = []

        # Search for Python files with agent keywords
        for py_file in repo_path.rglob("*.py"):
            # Skip test files and common directories
            if any(ignore in py_file.parts for ignore in [
                'test', 'tests', '__pycache__', 'venv', '.venv', 'node_modules'
            ]):
                continue

            # Check if filename contains agent keywords
            filename_lower = py_file.stem.lower()
            if any(keyword in filename_lower for keyword in self.AGENT_KEYWORDS):
                agent_files.append(py_file)

        # Search for JavaScript/TypeScript files
        for ext in ['*.js', '*.ts']:
            for js_file in repo_path.rglob(ext):
                if 'node_modules' in js_file.parts:
                    continue
                filename_lower = js_file.stem.lower()
                if any(keyword in filename_lower for keyword in self.AGENT_KEYWORDS):
                    agent_files.append(js_file)

        return agent_files[:50]  # Limit to prevent excessive processing

    def _analyze_file(self, file_path: Path, repo_path: Path) -> List[PotentialAgent]:
        """Analyze a single file for agent patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []

        patterns = []

        # Detect framework
        framework = self._detect_framework(content)

        # Detect interface types
        interfaces = self._detect_interfaces(content)

        # Detect agent classes/functions
        if file_path.suffix == '.py':
            patterns.extend(self._analyze_python_code(content, file_path))
        elif file_path.suffix in ['.js', '.ts']:
            patterns.extend(self._analyze_javascript_code(content, file_path))

        # If we found patterns, create PotentialAgent
        if patterns or framework or interfaces:
            agent_id = self._generate_agent_id(file_path, repo_path)
            name = self._generate_agent_name(file_path)

            # Calculate confidence score
            confidence = self._calculate_confidence(patterns, framework, interfaces)

            agent = PotentialAgent(
                agent_id=agent_id,
                name=name,
                file_path=str(file_path.relative_to(repo_path)),
                confidence=confidence,
                patterns=patterns,
                framework=framework,
                interface_hints=interfaces,
                description=f"Potential agent in {file_path.name}"
            )

            return [agent]

        return []

    def _detect_framework(self, content: str) -> Optional[AgentFramework]:
        """Detect agent framework used."""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return framework
        return None

    def _detect_interfaces(self, content: str) -> List[InterfaceType]:
        """Detect interface types used."""
        interfaces = []
        for interface_type, patterns in self.INTERFACE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if interface_type not in interfaces:
                        interfaces.append(interface_type)
                    break
        return interfaces

    def _analyze_python_code(self, content: str, file_path: Path) -> List[CodePattern]:
        """Analyze Python code for agent patterns."""
        patterns = []

        try:
            tree = ast.parse(content)

            # Look for agent classes
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_name = node.name.lower()
                    if any(keyword in class_name for keyword in self.AGENT_KEYWORDS):
                        patterns.append(CodePattern(
                            pattern_type="agent_class",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            confidence=0.9,
                            evidence=f"Class: {node.name}"
                        ))

                    # Check for agent-related base classes
                    for base in node.bases:
                        if isinstance(base, ast.Name):
                            base_name = base.id.lower()
                            if any(keyword in base_name for keyword in self.AGENT_KEYWORDS):
                                patterns.append(CodePattern(
                                    pattern_type="agent_inheritance",
                                    file_path=str(file_path),
                                    line_number=node.lineno,
                                    confidence=0.95,
                                    evidence=f"Class {node.name} inherits from {base.id}"
                                ))

                # Look for message handlers
                elif isinstance(node, ast.FunctionDef):
                    func_name = node.name.lower()
                    if any(keyword in func_name for keyword in ['handle', 'process', 'execute', 'run']):
                        for decorator in node.decorator_list:
                            if isinstance(decorator, ast.Name):
                                if decorator.id.lower() in ['subscribe', 'handler', 'route']:
                                    patterns.append(CodePattern(
                                        pattern_type="message_handler",
                                        file_path=str(file_path),
                                        line_number=node.lineno,
                                        confidence=0.8,
                                        evidence=f"Handler function: {node.name}"
                                    ))

        except SyntaxError:
            logger.debug(f"Could not parse {file_path} as Python")

        return patterns

    def _analyze_javascript_code(self, content: str, file_path: Path) -> List[CodePattern]:
        """Analyze JavaScript/TypeScript code for agent patterns."""
        patterns = []

        # Look for class definitions
        class_matches = re.finditer(r'class\s+(\w+)', content, re.IGNORECASE)
        for match in class_matches:
            class_name = match.group(1).lower()
            if any(keyword in class_name for keyword in self.AGENT_KEYWORDS):
                line_num = content[:match.start()].count('\n') + 1
                patterns.append(CodePattern(
                    pattern_type="agent_class",
                    file_path=str(file_path),
                    line_number=line_num,
                    confidence=0.9,
                    evidence=f"Class: {match.group(1)}"
                ))

        # Look for async function handlers
        handler_matches = re.finditer(
            r'async\s+function\s+(\w*(?:handle|process|execute)\w*)',
            content,
            re.IGNORECASE
        )
        for match in handler_matches:
            line_num = content[:match.start()].count('\n') + 1
            patterns.append(CodePattern(
                pattern_type="message_handler",
                file_path=str(file_path),
                line_number=line_num,
                confidence=0.7,
                evidence=f"Handler: {match.group(1)}"
            ))

        return patterns

    def _calculate_confidence(
        self,
        patterns: List[CodePattern],
        framework: Optional[AgentFramework],
        interfaces: List[InterfaceType]
    ) -> float:
        """Calculate confidence score for agent detection."""
        score = 0.0

        # Base score from patterns
        if patterns:
            avg_pattern_confidence = sum(p.confidence for p in patterns) / len(patterns)
            score += avg_pattern_confidence * 0.5

        # Framework detection adds confidence
        if framework and framework != AgentFramework.CUSTOM:
            score += 0.3

        # Interface detection adds confidence
        if interfaces:
            score += 0.2

        return min(score, 1.0)

    def _generate_agent_id(self, file_path: Path, repo_path: Path) -> str:
        """Generate unique agent ID."""
        relative_path = file_path.relative_to(repo_path)
        parts = list(relative_path.parts)
        parts[-1] = relative_path.stem  # Remove extension

        # Clean up parts
        cleaned = []
        for part in parts:
            # Remove common directories
            if part.lower() not in ['src', 'lib', 'app', 'core']:
                cleaned.append(part)

        return '-'.join(cleaned).lower().replace('_', '-')

    def _generate_agent_name(self, file_path: Path) -> str:
        """Generate human-readable agent name."""
        name = file_path.stem.replace('_', ' ').replace('-', ' ')
        return name.title()


def discover_agents_cli(repo_url: str) -> None:
    """CLI function to discover agents in a repository."""
    from .repo_scanner import RepositoryScanner

    # Scan repository
    scanner = RepositoryScanner()
    metadata = scanner.scan_repository(repo_url)

    # Discover agents
    discovery = AgentDiscoveryEngine()
    agents = discovery.discover_agents(metadata)

    # Print results
    print(f"\n{'='*70}")
    print(f"Agent Discovery Results")
    print(f"{'='*70}")
    print(f"Repository: {repo_url}")
    print(f"Total Agents Found: {len(agents)}")
    print(f"{'='*70}\n")

    for i, agent in enumerate(agents, 1):
        print(f"{i}. {agent.name}")
        print(f"   ID: {agent.agent_id}")
        print(f"   File: {agent.file_path}")
        print(f"   Confidence: {agent.confidence:.2%}")
        if agent.framework:
            print(f"   Framework: {agent.framework.value}")
        if agent.interface_hints:
            interfaces = ', '.join(i.value for i in agent.interface_hints)
            print(f"   Interfaces: {interfaces}")
        print(f"   Patterns: {len(agent.patterns)}")
        print()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        discover_agents_cli(sys.argv[1])
    else:
        print("Usage: python agent_discovery.py <repo_url>")
