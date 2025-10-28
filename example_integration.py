"""
Example: Complete workflow for integrating external agents into SOC-AI-AGENTS.

This script demonstrates:
1. Scanning a repository
2. Discovering agents
3. Generating manifests
4. Creating adapters
5. Registering with broker
6. Invoking external agents
"""

import asyncio
import os
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import integrator components
from integrator.repo_scanner import RepositoryScanner
from integrator.agent_discovery import AgentDiscoveryEngine
from integrator.manifest_generator import ManifestGenerator
from integrator.integration_broker import IntegrationBroker
from integrator.models import InterfaceType


async def integrate_repository(repo_url: str, openai_key: str = None):
    """
    Complete integration workflow for a repository.

    Args:
        repo_url: Repository URL or local path
        openai_key: Optional OpenAI API key for enhanced manifest generation
    """
    print("\n" + "="*70)
    print("UNIVERSAL AGENT INTEGRATOR - DEMO")
    print("="*70 + "\n")

    # ========================================================================
    # STEP 1: SCAN REPOSITORY
    # ========================================================================
    print("STEP 1: Scanning Repository")
    print("-" * 70)

    scanner = RepositoryScanner()
    repo_metadata = scanner.scan_repository(repo_url)

    print(f"✓ Repository scanned: {repo_metadata.repo_path}")
    print(f"  Languages: {', '.join(repo_metadata.languages.keys())}")
    print(f"  Entry points: {len(repo_metadata.entrypoints)}")
    print(f"  Has Docker: {repo_metadata.has_dockerfile}")
    print()

    # ========================================================================
    # STEP 2: DISCOVER AGENTS
    # ========================================================================
    print("STEP 2: Discovering Agents")
    print("-" * 70)

    discovery = AgentDiscoveryEngine()
    potential_agents = discovery.discover_agents(repo_metadata)

    print(f"✓ Found {len(potential_agents)} potential agents:")
    for i, agent in enumerate(potential_agents, 1):
        print(f"  {i}. {agent.name} (confidence: {agent.confidence:.0%})")
        if agent.framework:
            print(f"     Framework: {agent.framework.value}")
        if agent.interface_hints:
            print(f"     Interfaces: {', '.join(i.value for i in agent.interface_hints)}")
    print()

    # ========================================================================
    # STEP 3: GENERATE MANIFESTS
    # ========================================================================
    print("STEP 3: Generating Agent Manifests")
    print("-" * 70)

    generator = ManifestGenerator(openai_api_key=openai_key)
    manifests = []

    for agent in potential_agents[:5]:  # Limit to first 5 for demo
        print(f"  Generating manifest for {agent.name}...")
        manifest = generator.generate_manifest(agent, repo_metadata)
        manifests.append(manifest)
        print(f"  ✓ Manifest generated")
        print(f"    - Capabilities: {', '.join(manifest.capabilities[:3])}")
        print(f"    - Interface: {manifest.interface_type.value}")
        print(f"    - Security Level: {manifest.security_level.value}")

    print(f"\n✓ Generated {len(manifests)} manifests")
    print()

    # ========================================================================
    # STEP 4: INITIALIZE INTEGRATION BROKER
    # ========================================================================
    print("STEP 4: Initializing Integration Broker")
    print("-" * 70)

    broker = IntegrationBroker()
    await broker.start()

    print("✓ Integration Broker started")
    print()

    # ========================================================================
    # STEP 5: REGISTER AGENTS
    # ========================================================================
    print("STEP 5: Registering Agents with Broker")
    print("-" * 70)

    for manifest in manifests:
        agent_id = broker.register_agent(manifest)
        print(f"  ✓ Registered: {manifest.name} ({agent_id})")

    print(f"\n✓ All agents registered")
    print()

    # ========================================================================
    # STEP 6: DEMONSTRATE AGENT DISCOVERY
    # ========================================================================
    print("STEP 6: Testing Agent Discovery")
    print("-" * 70)

    # Test capability-based discovery
    test_capabilities = ['data_analysis', 'monitoring', 'llm_powered', 'api_endpoint']

    for capability in test_capabilities:
        agents = broker.discover_agents_by_capability(capability)
        if agents:
            print(f"  Agents with '{capability}': {', '.join(agents)}")

    print()

    # ========================================================================
    # STEP 7: INVOKE AGENTS (DEMO)
    # ========================================================================
    print("STEP 7: Testing Agent Invocation")
    print("-" * 70)

    # Get first registered agent
    agent_list = broker.list_agents()
    if agent_list:
        test_agent = agent_list[0]
        agent_id = test_agent['agent_id']

        print(f"  Testing agent: {test_agent['name']}")

        # Prepare test input
        test_input = {
            'message': 'Hello from SOC-AI-AGENTS!',
            'task': 'analyze',
            'data': {'test': True}
        }

        print(f"  Invoking with test input...")

        result = await broker.invoke_agent(
            agent_id=agent_id,
            capability='test',
            input_data=test_input,
            requester_id='demo_script'
        )

        if result.success:
            print(f"  ✓ Invocation successful!")
            print(f"    Execution time: {result.execution_time:.3f}s")
            if result.output_data:
                print(f"    Output: {result.output_data}")
        else:
            print(f"  ✗ Invocation failed: {result.error}")

    print()

    # ========================================================================
    # STEP 8: DISPLAY METRICS
    # ========================================================================
    print("STEP 8: Integration Metrics")
    print("-" * 70)

    metrics = broker.get_metrics()
    print(f"  Total Agents: {metrics['total_agents']}")
    print(f"  Healthy Agents: {metrics['healthy_agents']}")
    print(f"  Total Invocations: {metrics['total_invocations']}")
    print(f"  Success Rate: {metrics['success_rate']:.1f}%")
    print()

    # ========================================================================
    # STEP 9: LIST ALL AGENTS
    # ========================================================================
    print("STEP 9: Registered Agents Summary")
    print("-" * 70)

    for agent_info in agent_list:
        print(f"  Agent: {agent_info['name']}")
        print(f"    ID: {agent_info['agent_id']}")
        print(f"    Capabilities: {', '.join(agent_info['capabilities'][:3])}")
        print(f"    Interface: {agent_info['interface_type']}")
        print(f"    Health: {'✓ Healthy' if agent_info['is_healthy'] else '✗ Unhealthy'}")
        print(f"    Invocations: {agent_info['total_invocations']}")
        print()

    # ========================================================================
    # CLEANUP
    # ========================================================================
    print("Cleaning up...")
    await broker.stop()

    print("\n" + "="*70)
    print("INTEGRATION DEMO COMPLETE")
    print("="*70 + "\n")


async def demo_soc_integration():
    """
    Demonstrate how SOC agents can use external agents via the broker.
    """
    print("\n" + "="*70)
    print("SOC-AI-AGENTS ← → EXTERNAL AGENTS INTEGRATION")
    print("="*70 + "\n")

    # Initialize broker
    broker = IntegrationBroker()
    await broker.start()

    # Simulate: External malware analysis agent is already registered
    from integrator.models import AgentManifest, SecurityLevel, ImpactLevel, AgentFramework
    malware_manifest = AgentManifest(
        agent_id="malware-analyzer",
        name="Advanced Malware Analyzer",
        description="Analyzes files and URLs for malware",
        repo_url="https://github.com/example/malware-analyzer",
        file_path="analyzer/main.py",
        framework=AgentFramework.CUSTOM,
        language="Python",
        capabilities=["malware_analysis", "threat_detection", "file_analysis"],
        interface_type=InterfaceType.REST,
        endpoint="http://localhost:8001/analyze",
        security_level=SecurityLevel.HIGH,
        impact_level=ImpactLevel.READ_ONLY
    )

    broker.register_agent(malware_manifest)
    print("✓ External malware analyzer registered\n")

    # Simulate: SOC Analyst detects suspicious file
    print("Scenario: SOC Analyst detects suspicious file download")
    print("-" * 70)

    suspicious_file = {
        'file_hash': 'abc123def456',
        'file_url': 'https://suspicious-site.com/file.exe',
        'source_ip': '192.168.1.100',
        'alert_id': 'alert_001'
    }

    print(f"  Alert: Suspicious file detected")
    print(f"  File Hash: {suspicious_file['file_hash']}")
    print(f"  Source IP: {suspicious_file['source_ip']}")
    print()

    # SOC Analyst discovers available malware analysis agents
    print("SOC Analyst: Looking for malware analysis capability...")
    analyzers = broker.discover_agents_by_capability("malware_analysis")
    print(f"  Found {len(analyzers)} malware analyzers: {', '.join(analyzers)}")
    print()

    # Invoke external agent
    print("SOC Analyst: Invoking external malware analyzer...")
    result = await broker.invoke_agent(
        agent_id="malware-analyzer",
        capability="malware_analysis",
        input_data=suspicious_file,
        requester_id="soc_analyst"
    )

    if result.success:
        print("  ✓ Analysis complete!")
        print(f"  Execution time: {result.execution_time:.3f}s")
        # In real scenario, result.output_data would contain malware analysis
        print("  Result: File analysis complete (simulated)")
        print()
        print("SOC Analyst: Using analysis results to create remediation playbook...")
        print("  → Playbook: Block source IP + Quarantine file + Alert security team")
    else:
        print(f"  ✗ Analysis failed: {result.error}")

    print()

    # Show metrics
    metrics = broker.get_metrics()
    print("Integration Metrics:")
    print(f"  External Agents: {metrics['total_agents']}")
    print(f"  Total Invocations: {metrics['total_invocations']}")
    print(f"  Success Rate: {metrics['success_rate']:.1f}%")

    await broker.stop()

    print("\n" + "="*70)
    print("SOC INTEGRATION DEMO COMPLETE")
    print("="*70 + "\n")


def main():
    """Main entry point."""
    import sys

    print("\nUniversal Agent Integrator - Examples\n")
    print("Choose a demo:")
    print("1. Full integration workflow (scan repo → discover → integrate)")
    print("2. SOC + External Agents interaction demo")
    print("3. Both")
    print()

    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        repo_url = input("Enter repository URL or path (or press Enter for local demo): ").strip()
        if not repo_url:
            repo_url = "."  # Current directory
        openai_key = os.getenv('OPENAI_API_KEY')
        asyncio.run(integrate_repository(repo_url, openai_key))

    elif choice == "2":
        asyncio.run(demo_soc_integration())

    elif choice == "3":
        repo_url = input("Enter repository URL or path (or press Enter for local demo): ").strip()
        if not repo_url:
            repo_url = "."
        openai_key = os.getenv('OPENAI_API_KEY')
        asyncio.run(integrate_repository(repo_url, openai_key))
        print("\n\n")
        asyncio.run(demo_soc_integration())

    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
