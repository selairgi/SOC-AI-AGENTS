"""
Manifest Generator - Uses LLM + static analysis to generate agent manifests.
"""

import json
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

from .models import (
    PotentialAgent, AgentManifest, RepoMetadata,
    AgentFramework, InterfaceType, SecurityLevel, ImpactLevel, AdapterStatus
)

logger = logging.getLogger(__name__)


class ManifestGenerator:
    """Generates agent manifests using LLM analysis and static code inspection."""

    def __init__(self, openai_api_key: Optional[str] = None):
        self.openai_api_key = openai_api_key
        self.openai_available = False

        if openai_api_key:
            try:
                import openai
                self.openai = openai
                self.openai.api_key = openai_api_key
                self.openai_available = True
                logger.info("OpenAI integration enabled for manifest generation")
            except ImportError:
                logger.warning("OpenAI not available. Using heuristic-based generation only.")
        else:
            logger.info("No OpenAI API key provided. Using heuristic-based generation.")

    def generate_manifest(
        self,
        potential_agent: PotentialAgent,
        repo_metadata: RepoMetadata
    ) -> AgentManifest:
        """
        Generate complete agent manifest.

        Args:
            potential_agent: Discovered potential agent
            repo_metadata: Repository metadata

        Returns:
            Complete agent manifest
        """
        logger.info(f"Generating manifest for {potential_agent.name}")

        # Read agent code
        agent_file_path = Path(repo_metadata.repo_path) / potential_agent.file_path
        code_content = self._read_file(agent_file_path)

        # Read README if available
        readme_content = None
        if repo_metadata.readme_path:
            readme_path = Path(repo_metadata.repo_path) / repo_metadata.readme_path
            readme_content = self._read_file(readme_path)

        # Use LLM to analyze if available
        llm_analysis = None
        if self.openai_available and code_content:
            llm_analysis = self._analyze_with_llm(
                code_content, potential_agent, readme_content
            )

        # Generate manifest from all available information
        manifest = self._build_manifest(
            potential_agent, repo_metadata, code_content, readme_content, llm_analysis
        )

        logger.info(f"Manifest generated for {manifest.agent_id}")
        return manifest

    def _read_file(self, file_path: Path, max_lines: int = 500) -> Optional[str]:
        """Read file content, limited to max_lines."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line)
                return ''.join(lines)
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return None

    def _analyze_with_llm(
        self,
        code: str,
        potential_agent: PotentialAgent,
        readme: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Use LLM to analyze agent code and extract metadata."""
        try:
            prompt = self._build_analysis_prompt(code, potential_agent, readme)

            response = self.openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at analyzing code and extracting agent capabilities, interfaces, and security requirements. Always respond in valid JSON format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1500
            )

            result = response.choices[0].message.content
            # Try to parse JSON from response
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            else:
                logger.warning("Could not extract JSON from LLM response")
                return None

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return None

    def _build_analysis_prompt(
        self,
        code: str,
        potential_agent: PotentialAgent,
        readme: Optional[str]
    ) -> str:
        """Build prompt for LLM analysis."""
        prompt = f"""Analyze this agent code and extract the following information in JSON format:

Agent File: {potential_agent.file_path}
Detected Framework: {potential_agent.framework.value if potential_agent.framework else 'unknown'}
Detected Interfaces: {', '.join(i.value for i in potential_agent.interface_hints)}

Code:
```
{code[:3000]}  # Limit to 3000 chars
```
"""

        if readme:
            prompt += f"""
README:
```
{readme[:1000]}  # Limit to 1000 chars
```
"""

        prompt += """
Please provide a JSON object with the following fields:
{
  "description": "Clear description of what this agent does",
  "capabilities": ["list", "of", "capabilities"],
  "input_format": "Description of expected input format",
  "output_format": "Description of output format",
  "endpoint": "API endpoint if REST API (e.g., /api/analyze)",
  "port": 8000,
  "command": "CLI command if applicable (e.g., python agent.py --input file.txt)",
  "security_level": "low|medium|high|critical",
  "impact_level": "read_only|write|execute|admin",
  "required_permissions": ["list", "of", "required", "permissions"],
  "dependencies": ["list", "of", "key", "dependencies"],
  "environment_vars": {"KEY": "description"}
}

Return ONLY the JSON object, no additional text.
"""
        return prompt

    def _build_manifest(
        self,
        potential_agent: PotentialAgent,
        repo_metadata: RepoMetadata,
        code: Optional[str],
        readme: Optional[str],
        llm_analysis: Optional[Dict[str, Any]]
    ) -> AgentManifest:
        """Build manifest from all available information."""

        # Start with basic info
        manifest = AgentManifest(
            agent_id=potential_agent.agent_id,
            name=potential_agent.name,
            description=potential_agent.description,
            repo_url=repo_metadata.repo_url,
            file_path=potential_agent.file_path,
            framework=potential_agent.framework or AgentFramework.CUSTOM,
            language=self._detect_primary_language(repo_metadata),
        )

        # Apply LLM analysis if available
        if llm_analysis:
            manifest.description = llm_analysis.get('description', manifest.description)
            manifest.capabilities = llm_analysis.get('capabilities', [])
            manifest.endpoint = llm_analysis.get('endpoint')
            manifest.port = llm_analysis.get('port')
            manifest.command = llm_analysis.get('command')

            # Parse security level
            sec_level = llm_analysis.get('security_level', 'medium').upper()
            try:
                manifest.security_level = SecurityLevel[sec_level]
            except KeyError:
                manifest.security_level = SecurityLevel.MEDIUM

            # Parse impact level
            impact = llm_analysis.get('impact_level', 'read_only').upper()
            try:
                manifest.impact_level = ImpactLevel[impact]
            except KeyError:
                manifest.impact_level = ImpactLevel.READ_ONLY

            manifest.required_permissions = llm_analysis.get('required_permissions', [])
            manifest.dependencies = llm_analysis.get('dependencies', [])
            manifest.env_vars = llm_analysis.get('environment_vars', {})

        # Infer interface type
        if potential_agent.interface_hints:
            manifest.interface_type = potential_agent.interface_hints[0]
        else:
            manifest.interface_type = InterfaceType.CLI

        # Extract more info from code
        if code:
            self._extract_from_code(manifest, code)

        # Use Docker if available
        if repo_metadata.has_dockerfile:
            manifest.docker_image = f"{potential_agent.agent_id}:latest"

        # Set tags
        manifest.tags = self._generate_tags(manifest, repo_metadata)

        # Generate capabilities if not provided
        if not manifest.capabilities:
            manifest.capabilities = self._infer_capabilities(manifest, code)

        # Set status
        manifest.status = AdapterStatus.MANIFEST_GENERATED

        return manifest

    def _detect_primary_language(self, repo_metadata: RepoMetadata) -> str:
        """Detect primary programming language."""
        if not repo_metadata.languages:
            return "unknown"

        # Return language with highest percentage
        return max(repo_metadata.languages.items(), key=lambda x: x[1])[0]

    def _extract_from_code(self, manifest: AgentManifest, code: str) -> None:
        """Extract additional information from code analysis."""

        # Look for port numbers
        if not manifest.port:
            port_match = re.search(r'port["\s:=]+(\d+)', code, re.IGNORECASE)
            if port_match:
                manifest.port = int(port_match.group(1))

        # Look for API endpoints
        if manifest.interface_type == InterfaceType.REST and not manifest.endpoint:
            endpoint_match = re.search(r'@app\.(?:route|get|post)\(["\']([^"\']+)["\']', code)
            if endpoint_match:
                manifest.endpoint = endpoint_match.group(1)

        # Look for environment variables
        env_matches = re.findall(r'os\.environ(?:\.get)?\(["\']([^"\']+)["\']', code)
        for env_var in env_matches[:5]:  # Limit to 5
            if env_var not in manifest.env_vars:
                manifest.env_vars[env_var] = "Required environment variable"

    def _generate_tags(self, manifest: AgentManifest, repo_metadata: RepoMetadata) -> List[str]:
        """Generate tags for manifest."""
        tags = []

        # Add language tag
        tags.append(manifest.language.lower())

        # Add framework tag
        if manifest.framework != AgentFramework.CUSTOM:
            tags.append(manifest.framework.value)

        # Add interface tag
        tags.append(manifest.interface_type.value)

        # Add capability-based tags
        for cap in manifest.capabilities[:3]:
            tag = cap.lower().replace(' ', '-')
            tags.append(tag)

        return list(set(tags))

    def _infer_capabilities(self, manifest: AgentManifest, code: Optional[str]) -> List[str]:
        """Infer capabilities from manifest data and code."""
        capabilities = []

        # Based on name
        name_lower = manifest.name.lower()
        if 'analyze' in name_lower or 'analysis' in name_lower:
            capabilities.append('data_analysis')
        if 'monitor' in name_lower:
            capabilities.append('monitoring')
        if 'detect' in name_lower:
            capabilities.append('threat_detection')
        if 'report' in name_lower:
            capabilities.append('reporting')
        if 'chat' in name_lower or 'bot' in name_lower:
            capabilities.append('conversational')

        # Based on framework
        if manifest.framework in [AgentFramework.LANGCHAIN, AgentFramework.LANGGRAPH]:
            capabilities.append('llm_powered')

        # Based on interface
        if manifest.interface_type == InterfaceType.REST:
            capabilities.append('api_endpoint')

        # Generic capability if nothing else
        if not capabilities:
            capabilities.append('general_purpose')

        return capabilities


def generate_manifests_cli(repo_url: str, openai_key: Optional[str] = None) -> None:
    """CLI function to generate manifests for all agents in repository."""
    from .repo_scanner import RepositoryScanner
    from .agent_discovery import AgentDiscoveryEngine

    # Scan and discover
    scanner = RepositoryScanner()
    metadata = scanner.scan_repository(repo_url)

    discovery = AgentDiscoveryEngine()
    agents = discovery.discover_agents(metadata)

    # Generate manifests
    generator = ManifestGenerator(openai_api_key=openai_key)

    print(f"\n{'='*70}")
    print(f"Generating Manifests")
    print(f"{'='*70}\n")

    manifests = []
    for agent in agents:
        print(f"Processing {agent.name}...")
        manifest = generator.generate_manifest(agent, metadata)
        manifests.append(manifest)
        print(f"  ✓ Manifest generated")

    # Save manifests
    output_dir = Path("./manifests")
    output_dir.mkdir(exist_ok=True)

    for manifest in manifests:
        output_file = output_dir / f"{manifest.agent_id}.json"
        with open(output_file, 'w') as f:
            # Convert to dict (simplified)
            manifest_dict = {
                'agent_id': manifest.agent_id,
                'name': manifest.name,
                'description': manifest.description,
                'framework': manifest.framework.value,
                'language': manifest.language,
                'capabilities': manifest.capabilities,
                'interface_type': manifest.interface_type.value,
                'endpoint': manifest.endpoint,
                'port': manifest.port,
                'security_level': manifest.security_level.value,
                'impact_level': manifest.impact_level.value,
            }
            json.dump(manifest_dict, f, indent=2)
        print(f"  ✓ Saved to {output_file}")

    print(f"\n{'='*70}")
    print(f"Generated {len(manifests)} manifests")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) > 1:
        repo_url = sys.argv[1]
        api_key = os.getenv('OPENAI_API_KEY')
        generate_manifests_cli(repo_url, api_key)
    else:
        print("Usage: python manifest_generator.py <repo_url>")
        print("Set OPENAI_API_KEY environment variable for LLM-enhanced generation")
