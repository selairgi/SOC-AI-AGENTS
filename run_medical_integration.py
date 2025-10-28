"""
Run integration for Medical Diagnostics AI Agents repository.
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


async def integrate_medical_repo():
    """Integrate Medical Diagnostics AI Agents repository."""

    repo_url = "https://github.com/ahmadvh/AI-Agents-for-Medical-Diagnostics"

    print("\n" + "="*70)
    print("INTEGRATING MEDICAL DIAGNOSTICS AI AGENTS")
    print("="*70 + "\n")

    # ========================================================================
    # STEP 1: SCAN REPOSITORY
    # ========================================================================
    print("STEP 1: Scanning Repository")
    print("-" * 70)

    scanner = RepositoryScanner()

    try:
        repo_metadata = scanner.scan_repository(repo_url)

        print(f"Repository scanned: {repo_metadata.repo_path}")
        print(f"Languages detected:")
        for lang, pct in sorted(repo_metadata.languages.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {lang}: {pct}%")
        print(f"Entry points found: {len(repo_metadata.entrypoints)}")
        for ep in repo_metadata.entrypoints[:5]:
            print(f"  - {ep}")
        print(f"Has Docker: {repo_metadata.has_dockerfile}")
        print(f"Has Docker Compose: {repo_metadata.has_docker_compose}")
        print()

    except Exception as e:
        print(f"Error scanning repository: {e}")
        return

    # ========================================================================
    # STEP 2: DISCOVER AGENTS
    # ========================================================================
    print("STEP 2: Discovering Medical AI Agents")
    print("-" * 70)

    discovery = AgentDiscoveryEngine()
    potential_agents = discovery.discover_agents(repo_metadata)

    print(f"Found {len(potential_agents)} potential agents:\n")
    for i, agent in enumerate(potential_agents, 1):
        print(f"{i}. {agent.name}")
        print(f"   ID: {agent.agent_id}")
        print(f"   File: {agent.file_path}")
        print(f"   Confidence: {agent.confidence:.0%}")
        if agent.framework:
            print(f"   Framework: {agent.framework.value}")
        if agent.interface_hints:
            interfaces = ', '.join(i.value for i in agent.interface_hints)
            print(f"   Interfaces: {interfaces}")
        print(f"   Patterns detected: {len(agent.patterns)}")
        print()

    if not potential_agents:
        print("No agents discovered. Repository may not contain recognizable agent patterns.")
        return

    # ========================================================================
    # STEP 3: GENERATE MANIFESTS
    # ========================================================================
    print("STEP 3: Generating Agent Manifests")
    print("-" * 70)

    openai_key = os.getenv('OPENAI_API_KEY')
    if openai_key:
        print("Using OpenAI for enhanced manifest generation")
    else:
        print("OpenAI API key not found, using heuristic-based generation")

    generator = ManifestGenerator(openai_api_key=openai_key)
    manifests = []

    for agent in potential_agents[:10]:  # Limit to first 10
        print(f"\nGenerating manifest for: {agent.name}")
        try:
            manifest = generator.generate_manifest(agent, repo_metadata)
            manifests.append(manifest)

            print(f"  Manifest generated successfully")
            print(f"  - Description: {manifest.description[:100]}...")
            print(f"  - Capabilities: {', '.join(manifest.capabilities[:5])}")
            print(f"  - Interface: {manifest.interface_type.value}")
            print(f"  - Security Level: {manifest.security_level.value}")
            print(f"  - Impact Level: {manifest.impact_level.value}")

        except Exception as e:
            print(f"  Error generating manifest: {e}")
            continue

    print(f"\nSuccessfully generated {len(manifests)} manifests")
    print()

    # ========================================================================
    # STEP 4: INITIALIZE INTEGRATION BROKER
    # ========================================================================
    print("STEP 4: Initializing Integration Broker")
    print("-" * 70)

    broker = IntegrationBroker()
    await broker.start()

    print("Integration Broker started")
    print()

    # ========================================================================
    # STEP 5: REGISTER AGENTS
    # ========================================================================
    print("STEP 5: Registering Medical Agents with Broker")
    print("-" * 70)

    registered_count = 0
    for manifest in manifests:
        try:
            agent_id = broker.register_agent(manifest)
            print(f"  Registered: {manifest.name}")
            print(f"    - Agent ID: {agent_id}")
            print(f"    - Capabilities: {', '.join(manifest.capabilities[:3])}")
            registered_count += 1
        except Exception as e:
            print(f"  Error registering {manifest.name}: {e}")

    print(f"\nSuccessfully registered {registered_count} agents")
    print()

    # ========================================================================
    # STEP 6: DEMONSTRATE CAPABILITIES
    # ========================================================================
    print("STEP 6: Agent Capability Discovery")
    print("-" * 70)

    # Search for medical-related capabilities
    medical_capabilities = [
        'diagnosis', 'symptom_analysis', 'treatment_recommendation',
        'medical', 'patient', 'health', 'clinical'
    ]

    print("Searching for medical capabilities:\n")
    for capability in medical_capabilities:
        agents = broker.discover_agents_by_capability(capability)
        if agents:
            print(f"  '{capability}': {len(agents)} agent(s)")
            for agent_id in agents[:3]:  # Show first 3
                info = broker.get_agent_info(agent_id)
                if info:
                    print(f"    - {info['name']}")

    print()

    # ========================================================================
    # STEP 7: DEMO INVOCATION (IF AGENTS FOUND)
    # ========================================================================
    print("STEP 7: Testing Agent Invocation")
    print("-" * 70)

    agent_list = broker.list_agents()
    if agent_list:
        test_agent = agent_list[0]
        print(f"Testing agent: {test_agent['name']}")
        print(f"  Agent ID: {test_agent['agent_id']}")
        print(f"  Interface: {test_agent['interface_type']}")
        print()

        # Medical diagnostic test input
        test_input = {
            'patient_id': 'P12345',
            'symptoms': ['fever', 'cough', 'fatigue'],
            'medical_history': {
                'age': 45,
                'conditions': ['hypertension'],
                'medications': ['lisinopril']
            },
            'test_mode': True
        }

        print("Invoking with sample medical data...")
        print(f"  Symptoms: {', '.join(test_input['symptoms'])}")

        try:
            result = await broker.invoke_agent(
                agent_id=test_agent['agent_id'],
                capability='diagnosis',
                input_data=test_input,
                requester_id='medical_soc_system'
            )

            if result.success:
                print(f"\n  Invocation successful!")
                print(f"  Execution time: {result.execution_time:.3f}s")
                if result.output_data:
                    print(f"  Output received: {result.output_data}")
            else:
                print(f"\n  Invocation failed: {result.error}")
                print("  (This is expected if agent is not actually running)")

        except Exception as e:
            print(f"\n  Error during invocation: {e}")
            print("  (This is expected if agent is not actually running)")

    print()

    # ========================================================================
    # STEP 8: DISPLAY METRICS
    # ========================================================================
    print("STEP 8: Integration Metrics")
    print("-" * 70)

    metrics = broker.get_metrics()
    print(f"Total Agents Registered: {metrics['total_agents']}")
    print(f"Healthy Agents: {metrics['healthy_agents']}")
    print(f"Total Invocations: {metrics['total_invocations']}")
    print(f"Successful Invocations: {metrics['successful_invocations']}")
    print(f"Failed Invocations: {metrics['failed_invocations']}")
    if metrics['total_invocations'] > 0:
        print(f"Success Rate: {metrics['success_rate']:.1f}%")
    print()

    # ========================================================================
    # STEP 9: SHOW HOW SOC CAN USE THESE AGENTS
    # ========================================================================
    print("STEP 9: SOC Integration Example")
    print("-" * 70)

    print("""
Medical AI agents are now integrated with your SOC system!

Example SOC use cases:

1. PATIENT DATA BREACH ALERT
   - SOC detects unauthorized access to medical records
   - Discovers 'data_analysis' agents
   - Invokes medical AI agent to:
     * Assess severity of exposed data
     * Identify affected patients
     * Recommend compliance steps (HIPAA)

2. SUSPICIOUS MEDICAL DEVICE ACTIVITY
   - SOC monitors IoT medical devices
   - Detects anomalous behavior
   - Uses 'diagnosis' agents to:
     * Determine if device malfunction or attack
     * Assess patient safety risk
     * Generate remediation playbook

3. AUTOMATED MEDICAL LOG ANALYSIS
   - SOC ingests medical system logs
   - Uses 'symptom_analysis' agents to:
     * Identify patterns in system errors
     * Correlate with patient outcomes
     * Alert on critical failures

Example code in soc_analyst.py:
----------------------------------------
from integrator.integration_broker import IntegrationBroker

class SOCAnalyst:
    async def analyze_medical_alert(self, alert: Alert):
        # Discover medical AI agents
        agents = self.broker.discover_agents_by_capability("diagnosis")

        if agents:
            # Invoke for additional context
            result = await self.broker.invoke_agent(
                agent_id=agents[0],
                capability="diagnosis",
                input_data=alert.evidence
            )

            # Use in remediation playbook
            playbook = self.create_medical_playbook(alert, result.output_data)
----------------------------------------
""")

    # ========================================================================
    # STEP 10: LIST ALL REGISTERED AGENTS
    # ========================================================================
    print("STEP 10: Registered Medical Agents Summary")
    print("-" * 70)

    for i, agent_info in enumerate(agent_list, 1):
        print(f"\nAgent #{i}: {agent_info['name']}")
        print(f"  ID: {agent_info['agent_id']}")
        print(f"  Description: {agent_info['description'][:100]}...")
        print(f"  Capabilities: {', '.join(agent_info['capabilities'][:5])}")
        print(f"  Interface: {agent_info['interface_type']}")
        print(f"  Framework: {agent_info['framework']}")
        print(f"  Security Level: {agent_info['security_level']}")
        print(f"  Health Status: {'Healthy' if agent_info['is_healthy'] else 'Unhealthy'}")
        print(f"  Total Invocations: {agent_info['total_invocations']}")

    # ========================================================================
    # CLEANUP
    # ========================================================================
    print("\n" + "-" * 70)
    print("Cleaning up...")
    await broker.stop()

    print("\n" + "="*70)
    print("MEDICAL DIAGNOSTICS AI AGENTS INTEGRATION COMPLETE!")
    print("="*70 + "\n")

    print("Next steps:")
    print("1. Review the discovered agents above")
    print("2. Deploy actual medical agents if needed")
    print("3. Integrate broker into soc_analyst.py")
    print("4. Test with real medical security alerts")
    print()


if __name__ == "__main__":
    asyncio.run(integrate_medical_repo())
