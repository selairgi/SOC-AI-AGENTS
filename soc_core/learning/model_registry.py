"""
Model Registry for SOC Agents.

Manages model versions and metadata:
- model_registry/<agent>/vX/
  - metrics.json
  - config.json
  - training_summary.json

NO auto-deployment - manual only.
"""

import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class ModelVersion:
    """Represents a model version."""
    agent: str
    version: str
    metrics: Dict[str, float]
    trained_at: str
    deployed: bool = False
    deployed_at: Optional[str] = None
    path: str = ""


class ModelRegistry:
    """
    Registry for SOC agent models.

    Tracks all model versions and their metadata.
    Supports manual deployment (no auto-deploy).
    """

    def __init__(
        self,
        base_path: str = None,
        logger: Optional[logging.Logger] = None
    ):
        self.logger = logger or logging.getLogger("ModelRegistry")

        # Default path
        if base_path is None:
            project_root = Path(__file__).parent.parent.parent
            base_path = str(project_root / "model_registry")

        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Active versions per agent
        self._active_versions: Dict[str, str] = {}

        # Load active versions
        self._load_active_versions()

        self.logger.info(f"ModelRegistry initialized: {self.base_path}")

    def _load_active_versions(self) -> None:
        """Load active versions from disk."""
        active_file = self.base_path / "active_versions.json"

        if active_file.exists():
            with open(active_file, "r") as f:
                self._active_versions = json.load(f)
                self.logger.info(f"Loaded active versions: {self._active_versions}")

    def _save_active_versions(self) -> None:
        """Save active versions to disk."""
        active_file = self.base_path / "active_versions.json"

        with open(active_file, "w") as f:
            json.dump(self._active_versions, f, indent=2)

    def register(
        self,
        agent: str,
        version: str,
        metrics: Dict[str, float],
        config: Dict[str, Any] = None
    ) -> ModelVersion:
        """
        Register a new model version.

        Args:
            agent: Agent name
            version: Model version
            metrics: Training metrics
            config: Model configuration

        Returns:
            ModelVersion object
        """
        version_dir = self.base_path / agent / f"v{version}"
        version_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).isoformat()

        # Save metrics
        metrics_file = version_dir / "metrics.json"
        with open(metrics_file, "w") as f:
            json.dump({
                "version": version,
                "agent": agent,
                "metrics": metrics,
                "registered_at": now,
            }, f, indent=2)

        # Save config
        if config:
            config_file = version_dir / "config.json"
            with open(config_file, "w") as f:
                json.dump(config, f, indent=2)

        model = ModelVersion(
            agent=agent,
            version=version,
            metrics=metrics,
            trained_at=now,
            deployed=False,
            path=str(version_dir)
        )

        self.logger.info(f"Registered model: {agent} v{version}")
        return model

    def list_versions(self, agent: str) -> List[ModelVersion]:
        """
        List all versions for an agent.

        Args:
            agent: Agent name

        Returns:
            List of ModelVersion objects
        """
        agent_dir = self.base_path / agent

        if not agent_dir.exists():
            return []

        versions = []
        for version_dir in sorted(agent_dir.iterdir()):
            if version_dir.is_dir() and version_dir.name.startswith("v"):
                metrics_file = version_dir / "metrics.json"

                if metrics_file.exists():
                    with open(metrics_file, "r") as f:
                        data = json.load(f)

                    version = version_dir.name[1:]  # Remove 'v' prefix
                    versions.append(ModelVersion(
                        agent=agent,
                        version=version,
                        metrics=data.get("metrics", {}),
                        trained_at=data.get("registered_at", ""),
                        deployed=self._active_versions.get(agent) == version,
                        path=str(version_dir)
                    ))

        return versions

    def get_active_version(self, agent: str) -> Optional[str]:
        """Get the active (deployed) version for an agent."""
        return self._active_versions.get(agent)

    def get_version(self, agent: str, version: str) -> Optional[ModelVersion]:
        """
        Get a specific model version.

        Args:
            agent: Agent name
            version: Model version

        Returns:
            ModelVersion or None
        """
        version_dir = self.base_path / agent / f"v{version}"
        metrics_file = version_dir / "metrics.json"

        if not metrics_file.exists():
            return None

        with open(metrics_file, "r") as f:
            data = json.load(f)

        return ModelVersion(
            agent=agent,
            version=version,
            metrics=data.get("metrics", {}),
            trained_at=data.get("registered_at", ""),
            deployed=self._active_versions.get(agent) == version,
            path=str(version_dir)
        )

    def deploy(self, agent: str, version: str) -> bool:
        """
        Deploy a model version (manual only).

        Args:
            agent: Agent name
            version: Version to deploy

        Returns:
            True if deployed successfully
        """
        version_dir = self.base_path / agent / f"v{version}"

        if not version_dir.exists():
            self.logger.error(f"Version not found: {agent} v{version}")
            return False

        # Update active version
        old_version = self._active_versions.get(agent)
        self._active_versions[agent] = version
        self._save_active_versions()

        # Update deployment timestamp
        metrics_file = version_dir / "metrics.json"
        if metrics_file.exists():
            with open(metrics_file, "r") as f:
                data = json.load(f)

            data["deployed"] = True
            data["deployed_at"] = datetime.now(timezone.utc).isoformat()

            with open(metrics_file, "w") as f:
                json.dump(data, f, indent=2)

        self.logger.info(
            f"Deployed {agent} v{version} (was: {old_version or 'none'})"
        )

        return True

    def rollback(self, agent: str, version: str) -> bool:
        """
        Rollback to a previous version.

        Args:
            agent: Agent name
            version: Version to rollback to

        Returns:
            True if rollback successful
        """
        return self.deploy(agent, version)

    def get_latest_version(self, agent: str) -> Optional[str]:
        """Get the latest registered version for an agent."""
        versions = self.list_versions(agent)

        if not versions:
            return None

        # Sort by version (assumes semantic or date-based versioning)
        versions.sort(key=lambda v: v.version, reverse=True)
        return versions[0].version

    def compare_versions(
        self,
        agent: str,
        version_a: str,
        version_b: str
    ) -> Dict[str, Any]:
        """
        Compare metrics between two versions.

        Args:
            agent: Agent name
            version_a: First version
            version_b: Second version

        Returns:
            Comparison result
        """
        model_a = self.get_version(agent, version_a)
        model_b = self.get_version(agent, version_b)

        if not model_a or not model_b:
            return {"error": "One or both versions not found"}

        metrics_a = model_a.metrics
        metrics_b = model_b.metrics

        comparison = {
            "agent": agent,
            "version_a": version_a,
            "version_b": version_b,
            "metrics_comparison": {},
            "winner": None,
        }

        # Compare each metric
        wins_a = 0
        wins_b = 0

        for metric in set(metrics_a.keys()) | set(metrics_b.keys()):
            val_a = metrics_a.get(metric, 0)
            val_b = metrics_b.get(metric, 0)

            comparison["metrics_comparison"][metric] = {
                "version_a": val_a,
                "version_b": val_b,
                "diff": val_b - val_a,
                "winner": version_a if val_a > val_b else version_b if val_b > val_a else "tie"
            }

            if val_a > val_b:
                wins_a += 1
            elif val_b > val_a:
                wins_b += 1

        comparison["winner"] = (
            version_a if wins_a > wins_b else
            version_b if wins_b > wins_a else
            "tie"
        )

        return comparison

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        agents = [d.name for d in self.base_path.iterdir() if d.is_dir() and not d.name.startswith('.')]

        stats = {
            "agents": agents,
            "active_versions": self._active_versions,
            "total_versions": {},
        }

        for agent in agents:
            versions = self.list_versions(agent)
            stats["total_versions"][agent] = len(versions)

        return stats
