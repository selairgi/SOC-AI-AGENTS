"""
Repository Scanner - Clone and analyze repositories for agent discovery.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter
import logging

from .models import RepoMetadata, EntryPoint

logger = logging.getLogger(__name__)


class RepositoryScanner:
    """Scans repositories to extract metadata for agent discovery."""

    def __init__(self, workspace_dir: str = "./workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(exist_ok=True)

    def scan_repository(self, repo_url: str) -> RepoMetadata:
        """
        Clone and scan repository, extracting all relevant metadata.

        Args:
            repo_url: Git repository URL or local path

        Returns:
            RepoMetadata with all extracted information
        """
        logger.info(f"Scanning repository: {repo_url}")

        # Clone or validate local path
        if repo_url.startswith(("http://", "https://", "git@")):
            repo_path = self._clone_repository(repo_url)
        else:
            repo_path = Path(repo_url)
            if not repo_path.exists():
                raise ValueError(f"Repository path does not exist: {repo_url}")

        # Gather metadata
        metadata = RepoMetadata(
            repo_url=repo_url,
            repo_path=str(repo_path),
            languages=self.detect_languages(repo_path),
            has_dockerfile=self._check_file_exists(repo_path, "Dockerfile"),
            has_docker_compose=self._check_file_exists(repo_path, "docker-compose.yml") or
                               self._check_file_exists(repo_path, "docker-compose.yaml"),
            package_files=self._find_package_files(repo_path),
            entrypoints=self._find_entrypoints(repo_path),
            readme_path=self._find_readme(repo_path),
            openapi_specs=self._find_openapi_specs(repo_path),
            test_files=self._find_test_files(repo_path),
            dependencies=self._extract_dependencies(repo_path)
        )

        logger.info(f"Scan complete. Found {len(metadata.entrypoints)} entry points")
        return metadata

    def _clone_repository(self, repo_url: str) -> Path:
        """Clone git repository to workspace."""
        # Extract repo name
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
        repo_path = self.workspace_dir / repo_name

        if repo_path.exists():
            logger.info(f"Repository already exists: {repo_path}")
            # Try to pull latest changes
            try:
                subprocess.run(
                    ["git", "pull"],
                    cwd=repo_path,
                    capture_output=True,
                    timeout=60
                )
            except Exception as e:
                logger.warning(f"Could not pull latest changes: {e}")
        else:
            logger.info(f"Cloning repository to {repo_path}")
            subprocess.run(
                ["git", "clone", repo_url, str(repo_path)],
                capture_output=True,
                timeout=300,
                check=True
            )

        return repo_path

    def detect_languages(self, repo_path: Path) -> Dict[str, float]:
        """
        Detect programming languages in repository.

        Returns:
            Dict mapping language to percentage (0-100)
        """
        language_extensions = {
            'Python': ['.py'],
            'JavaScript': ['.js', '.jsx'],
            'TypeScript': ['.ts', '.tsx'],
            'Go': ['.go'],
            'Java': ['.java'],
            'Rust': ['.rs'],
            'C++': ['.cpp', '.cc', '.cxx', '.hpp', '.h'],
            'C': ['.c', '.h'],
            'Ruby': ['.rb'],
            'PHP': ['.php'],
            'C#': ['.cs'],
            'Shell': ['.sh', '.bash'],
            'Dockerfile': ['Dockerfile'],
        }

        file_counts = Counter()
        total_files = 0

        for ext_list in language_extensions.values():
            for ext in ext_list:
                if ext.startswith('.'):
                    files = list(repo_path.rglob(f"*{ext}"))
                else:
                    files = list(repo_path.rglob(ext))

                # Filter out common directories to ignore
                files = [f for f in files if not any(
                    ignore in f.parts
                    for ignore in ['node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build']
                )]

                for lang, exts in language_extensions.items():
                    if ext in exts:
                        file_counts[lang] += len(files)
                        total_files += len(files)

        # Calculate percentages
        if total_files == 0:
            return {}

        return {
            lang: round((count / total_files) * 100, 2)
            for lang, count in file_counts.items()
            if count > 0
        }

    def _check_file_exists(self, repo_path: Path, filename: str) -> bool:
        """Check if file exists in repository."""
        return (repo_path / filename).exists()

    def _find_package_files(self, repo_path: Path) -> List[str]:
        """Find package dependency files."""
        package_files = [
            'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile',
            'package.json', 'package-lock.json', 'yarn.lock',
            'go.mod', 'go.sum',
            'Cargo.toml', 'Cargo.lock',
            'pom.xml', 'build.gradle',
            'Gemfile', 'composer.json'
        ]

        found = []
        for pkg_file in package_files:
            matches = list(repo_path.rglob(pkg_file))
            found.extend([str(m.relative_to(repo_path)) for m in matches])

        return found

    def _find_entrypoints(self, repo_path: Path) -> List[str]:
        """Find potential entry points (main files, CLI scripts)."""
        entrypoint_patterns = [
            '**/main.py', '**/app.py', '**/server.py', '**/agent.py', '**/worker.py',
            '**/main.go', '**/server.go',
            '**/main.js', '**/server.js', '**/index.js', '**/app.js',
            '**/main.ts', '**/server.ts', '**/index.ts', '**/app.ts',
            '**/Main.java', '**/Application.java',
            '**/main.rs'
        ]

        found = []
        for pattern in entrypoint_patterns:
            matches = list(repo_path.glob(pattern))
            # Filter out node_modules, venv, etc.
            matches = [m for m in matches if not any(
                ignore in m.parts
                for ignore in ['node_modules', 'venv', '.venv', '__pycache__', 'test', 'tests']
            )]
            found.extend([str(m.relative_to(repo_path)) for m in matches])

        return list(set(found))

    def _find_readme(self, repo_path: Path) -> Optional[str]:
        """Find README file."""
        readme_patterns = ['README.md', 'README.txt', 'README', 'readme.md']
        for pattern in readme_patterns:
            readme_path = repo_path / pattern
            if readme_path.exists():
                return str(readme_path.relative_to(repo_path))
        return None

    def _find_openapi_specs(self, repo_path: Path) -> List[str]:
        """Find OpenAPI/Swagger specification files."""
        patterns = [
            '**/*openapi*.json', '**/*openapi*.yaml', '**/*openapi*.yml',
            '**/*swagger*.json', '**/*swagger*.yaml', '**/*swagger*.yml'
        ]

        found = []
        for pattern in patterns:
            matches = list(repo_path.rglob(pattern))
            found.extend([str(m.relative_to(repo_path)) for m in matches])

        return list(set(found))

    def _find_test_files(self, repo_path: Path) -> List[str]:
        """Find test files."""
        patterns = [
            '**/test_*.py', '**/*_test.py', '**/tests/**/*.py',
            '**/test_*.js', '**/*_test.js', '**/*.test.js', '**/*.spec.js',
            '**/test_*.go', '**/*_test.go',
            '**/*Test.java', '**/*Tests.java'
        ]

        found = []
        for pattern in patterns:
            matches = list(repo_path.glob(pattern))
            found.extend([str(m.relative_to(repo_path)) for m in matches[:10]])  # Limit to 10 per pattern

        return list(set(found))

    def _extract_dependencies(self, repo_path: Path) -> Dict[str, List[str]]:
        """Extract dependencies from package files."""
        dependencies = {}

        # Python requirements.txt
        req_file = repo_path / 'requirements.txt'
        if req_file.exists():
            try:
                with open(req_file, 'r', encoding='utf-8') as f:
                    deps = [
                        line.strip().split('==')[0].split('>=')[0].split('<=')[0]
                        for line in f
                        if line.strip() and not line.startswith('#')
                    ]
                    dependencies['python'] = deps[:20]  # Limit to 20
            except Exception as e:
                logger.warning(f"Could not parse requirements.txt: {e}")

        # Node.js package.json
        pkg_file = repo_path / 'package.json'
        if pkg_file.exists():
            try:
                with open(pkg_file, 'r', encoding='utf-8') as f:
                    pkg_data = json.load(f)
                    deps = list(pkg_data.get('dependencies', {}).keys())
                    dependencies['javascript'] = deps[:20]  # Limit to 20
            except Exception as e:
                logger.warning(f"Could not parse package.json: {e}")

        # Go go.mod
        go_mod = repo_path / 'go.mod'
        if go_mod.exists():
            try:
                with open(go_mod, 'r', encoding='utf-8') as f:
                    deps = []
                    for line in f:
                        if line.strip().startswith('require'):
                            continue
                        match = re.match(r'\s+([^\s]+)', line)
                        if match:
                            deps.append(match.group(1))
                    dependencies['go'] = deps[:20]  # Limit to 20
            except Exception as e:
                logger.warning(f"Could not parse go.mod: {e}")

        return dependencies


def scan_repository_cli(repo_url: str) -> None:
    """CLI function to scan a repository and print results."""
    scanner = RepositoryScanner()
    metadata = scanner.scan_repository(repo_url)

    print(f"\n{'='*70}")
    print(f"Repository Scan Results")
    print(f"{'='*70}")
    print(f"Repository: {metadata.repo_url}")
    print(f"Path: {metadata.repo_path}")
    print(f"\nLanguages Detected:")
    for lang, pct in sorted(metadata.languages.items(), key=lambda x: x[1], reverse=True):
        print(f"  {lang}: {pct}%")

    print(f"\nDocker Support:")
    print(f"  Dockerfile: {metadata.has_dockerfile}")
    print(f"  Docker Compose: {metadata.has_docker_compose}")

    print(f"\nEntry Points Found: {len(metadata.entrypoints)}")
    for ep in metadata.entrypoints[:10]:
        print(f"  - {ep}")

    print(f"\nDependencies:")
    for lang, deps in metadata.dependencies.items():
        print(f"  {lang}: {len(deps)} packages")

    print(f"\nOpenAPI Specs: {len(metadata.openapi_specs)}")
    for spec in metadata.openapi_specs:
        print(f"  - {spec}")

    print(f"{'='*70}\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_repository_cli(sys.argv[1])
    else:
        print("Usage: python repo_scanner.py <repo_url>")
