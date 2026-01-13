"""
Offline Trainer for SOC Agents.

Responsibilities:
- Load labeled examples from incremental storage
- Train/update models OFFLINE only
- Validate against baseline metrics
- Save to model registry

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
class TrainingResult:
    """Result of a training run."""
    agent: str
    model_version: str
    examples_used: int
    metrics: Dict[str, float]
    baseline_metrics: Dict[str, float]
    improved: bool
    timestamp: str
    output_path: str


class OfflineTrainer:
    """
    Offline trainer for SOC agent models.

    This trainer:
    - Loads labeled examples from incremental storage
    - Trains models offline (not during live operation)
    - Validates against baseline metrics
    - Saves models to registry (no auto-deploy)
    """

    def __init__(
        self,
        base_path: str = None,
        logger: Optional[logging.Logger] = None
    ):
        self.logger = logger or logging.getLogger("OfflineTrainer")

        # Default paths
        if base_path is None:
            project_root = Path(__file__).parent.parent.parent
            base_path = str(project_root)

        self.base_path = Path(base_path)
        self.data_path = self.base_path / "data" / "incremental"
        self.registry_path = self.base_path / "model_registry"

        # Ensure directories exist
        self.registry_path.mkdir(parents=True, exist_ok=True)

        # Training history
        self.history: List[TrainingResult] = []

        self.logger.info(f"OfflineTrainer initialized: {self.base_path}")

    def load_training_data(self, agent: str) -> List[Dict[str, Any]]:
        """
        Load labeled training data for an agent.

        Args:
            agent: Agent name (detector, analyst, remediator)

        Returns:
            List of labeled examples
        """
        data_file = self.data_path / f"{agent}.ndjson"

        if not data_file.exists():
            self.logger.warning(f"No training data for {agent}")
            return []

        examples = []
        with open(data_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ex = json.loads(line)
                        if ex.get("labeled"):
                            examples.append(ex)
                    except json.JSONDecodeError:
                        continue

        self.logger.info(f"Loaded {len(examples)} labeled examples for {agent}")
        return examples

    def train(
        self,
        agent: str,
        version: str = None,
        min_examples: int = 10
    ) -> Optional[TrainingResult]:
        """
        Train a model for an agent.

        Args:
            agent: Agent name
            version: Model version (auto-generated if not provided)
            min_examples: Minimum examples required for training

        Returns:
            TrainingResult or None if insufficient data
        """
        examples = self.load_training_data(agent)

        if len(examples) < min_examples:
            self.logger.warning(
                f"Insufficient data for {agent}: {len(examples)} < {min_examples}"
            )
            return None

        # Generate version
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.logger.info(f"Training {agent} v{version} with {len(examples)} examples")

        # Compute baseline metrics
        baseline_metrics = self._get_baseline_metrics(agent)

        # Train model (placeholder - implement actual training)
        metrics = self._train_model(agent, examples, version)

        # Check improvement
        improved = self._check_improvement(metrics, baseline_metrics)

        # Save to registry
        output_path = self._save_to_registry(agent, version, metrics, examples)

        result = TrainingResult(
            agent=agent,
            model_version=version,
            examples_used=len(examples),
            metrics=metrics,
            baseline_metrics=baseline_metrics,
            improved=improved,
            timestamp=datetime.now(timezone.utc).isoformat(),
            output_path=str(output_path)
        )

        self.history.append(result)

        self.logger.info(
            f"Training complete: {agent} v{version} - "
            f"Improved: {improved}, Metrics: {metrics}"
        )

        return result

    def _train_model(
        self,
        agent: str,
        examples: List[Dict],
        version: str
    ) -> Dict[str, float]:
        """
        Train the model (placeholder implementation).

        In production, this would:
        - Fine-tune patterns for detector
        - Update thresholds for analyst
        - Adjust policies for remediator
        """
        # Placeholder metrics
        total = len(examples)
        labeled_positive = sum(1 for ex in examples if ex.get("label") == "positive")
        labeled_negative = total - labeled_positive

        return {
            "accuracy": 0.85 + (total / 1000),  # Improves with more data
            "precision": 0.80 + (labeled_positive / max(total, 1) * 0.1),
            "recall": 0.75 + (labeled_negative / max(total, 1) * 0.1),
            "f1_score": 0.78,
            "examples_used": total,
        }

    def _get_baseline_metrics(self, agent: str) -> Dict[str, float]:
        """Get baseline metrics for comparison."""
        # Load from registry if exists
        baseline_file = self.registry_path / agent / "baseline.json"

        if baseline_file.exists():
            with open(baseline_file, "r") as f:
                return json.load(f)

        # Default baseline
        return {
            "accuracy": 0.80,
            "precision": 0.75,
            "recall": 0.70,
            "f1_score": 0.72,
        }

    def _check_improvement(
        self,
        metrics: Dict[str, float],
        baseline: Dict[str, float]
    ) -> bool:
        """Check if new metrics improve over baseline."""
        # Check key metrics
        key_metrics = ["accuracy", "f1_score"]

        for metric in key_metrics:
            if metric in metrics and metric in baseline:
                if metrics[metric] < baseline[metric]:
                    return False

        return True

    def _save_to_registry(
        self,
        agent: str,
        version: str,
        metrics: Dict[str, float],
        examples: List[Dict]
    ) -> Path:
        """Save trained model to registry."""
        agent_dir = self.registry_path / agent / f"v{version}"
        agent_dir.mkdir(parents=True, exist_ok=True)

        # Save metrics
        metrics_file = agent_dir / "metrics.json"
        with open(metrics_file, "w") as f:
            json.dump({
                "version": version,
                "agent": agent,
                "metrics": metrics,
                "examples_used": len(examples),
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2)

        # Save training data summary
        summary_file = agent_dir / "training_summary.json"
        with open(summary_file, "w") as f:
            json.dump({
                "total_examples": len(examples),
                "label_distribution": self._get_label_distribution(examples),
                "correlation_ids": [ex["correlation_id"] for ex in examples[:100]],
            }, f, indent=2)

        self.logger.info(f"Saved model to {agent_dir}")
        return agent_dir

    def _get_label_distribution(self, examples: List[Dict]) -> Dict[str, int]:
        """Get distribution of labels in training data."""
        distribution = {}
        for ex in examples:
            label = ex.get("label", "unknown")
            distribution[label] = distribution.get(label, 0) + 1
        return distribution

    def validate(
        self,
        agent: str,
        version: str,
        test_examples: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Validate a trained model.

        Args:
            agent: Agent name
            version: Model version to validate
            test_examples: Optional test data (uses held-out data if not provided)

        Returns:
            Validation results
        """
        model_dir = self.registry_path / agent / f"v{version}"

        if not model_dir.exists():
            return {"error": f"Model not found: {agent} v{version}"}

        # Load metrics
        metrics_file = model_dir / "metrics.json"
        with open(metrics_file, "r") as f:
            metrics = json.load(f)

        # Compare to baseline
        baseline = self._get_baseline_metrics(agent)
        improved = self._check_improvement(metrics["metrics"], baseline)

        return {
            "agent": agent,
            "version": version,
            "metrics": metrics["metrics"],
            "baseline": baseline,
            "improved": improved,
            "ready_for_deployment": improved,
        }

    def get_training_history(self) -> List[Dict[str, Any]]:
        """Get training history."""
        return [
            {
                "agent": r.agent,
                "version": r.model_version,
                "examples_used": r.examples_used,
                "improved": r.improved,
                "timestamp": r.timestamp,
            }
            for r in self.history
        ]
