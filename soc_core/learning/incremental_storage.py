"""
Incremental Storage for Agent Learning.

Stores training examples in NDJSON format for each agent:
- data/incremental/detector.ndjson
- data/incremental/analyst.ndjson
- data/incremental/remediator.ndjson

Examples can be labeled via human feedback for supervised learning.
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Iterator
from dataclasses import dataclass, asdict
import threading


@dataclass
class TrainingExample:
    """A single training example for an agent."""
    example_id: str
    correlation_id: str
    timestamp: str
    agent: str
    model_version: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    label: Optional[str] = None
    labeled: bool = False
    feedback_by: Optional[str] = None
    feedback_at: Optional[str] = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IncrementalStorage:
    """
    Store and retrieve incremental learning examples.

    Each agent writes examples to data/incremental/<agent>.ndjson
    Format: One JSON object per line (NDJSON)
    """

    def __init__(
        self,
        agent_name: str,
        base_path: str = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize incremental storage for an agent.

        Args:
            agent_name: Name of the agent (detector, analyst, remediator)
            base_path: Base directory for incremental data
            logger: Optional logger
        """
        self.agent_name = agent_name
        self.logger = logger or logging.getLogger(f"IncrementalStorage.{agent_name}")

        # Default path: project_root/data/incremental/
        if base_path is None:
            project_root = Path(__file__).parent.parent.parent
            base_path = str(project_root / "data" / "incremental")

        self.base_path = Path(base_path)
        self.file_path = self.base_path / f"{agent_name}.ndjson"

        # Ensure directory exists
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Thread safety
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "examples_stored": 0,
            "examples_labeled": 0,
            "last_write": None,
        }

        self.logger.info(f"IncrementalStorage initialized: {self.file_path}")

    def store(
        self,
        correlation_id: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        model_version: str = "1.0.0",
        label: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store a training example.

        Args:
            correlation_id: Correlation ID for tracing
            input_data: Input to the agent
            output_data: Output from the agent
            model_version: Version of the model used
            label: Optional human-provided label
            metadata: Optional additional metadata

        Returns:
            Example ID
        """
        example = TrainingExample(
            example_id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=self.agent_name,
            model_version=model_version,
            input_data=input_data,
            output_data=output_data,
            label=label,
            labeled=label is not None,
            metadata=metadata or {}
        )

        with self._lock:
            try:
                with open(self.file_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(example.to_dict()) + "\n")

                self.stats["examples_stored"] += 1
                self.stats["last_write"] = example.timestamp

                if label:
                    self.stats["examples_labeled"] += 1

                self.logger.debug(f"Stored example: {example.example_id[:8]}...")

            except Exception as e:
                self.logger.error(f"Failed to store example: {e}")
                raise

        return example.example_id

    def add_label(
        self,
        example_id: str,
        label: str,
        feedback_by: str = "human"
    ) -> bool:
        """
        Add a label to an existing example.

        Note: This rewrites the file - for production, use a database.

        Args:
            example_id: The example to label
            label: The label to add
            feedback_by: Who provided the label

        Returns:
            True if labeled successfully
        """
        with self._lock:
            try:
                examples = list(self.iterate())
                updated = False

                for ex in examples:
                    if ex.get("example_id") == example_id:
                        ex["label"] = label
                        ex["labeled"] = True
                        ex["feedback_by"] = feedback_by
                        ex["feedback_at"] = datetime.now(timezone.utc).isoformat()
                        updated = True
                        break

                if updated:
                    # Rewrite file
                    with open(self.file_path, "w", encoding="utf-8") as f:
                        for ex in examples:
                            f.write(json.dumps(ex) + "\n")

                    self.stats["examples_labeled"] += 1
                    self.logger.info(f"Labeled example: {example_id[:8]}... = {label}")

                return updated

            except Exception as e:
                self.logger.error(f"Failed to add label: {e}")
                return False

    def iterate(self) -> Iterator[Dict[str, Any]]:
        """
        Iterate over all stored examples.

        Yields:
            Each example as a dictionary
        """
        if not self.file_path.exists():
            return

        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Skipping malformed line: {e}")

    def get_labeled(self) -> List[Dict[str, Any]]:
        """Get all labeled examples."""
        return [ex for ex in self.iterate() if ex.get("labeled")]

    def get_unlabeled(self) -> List[Dict[str, Any]]:
        """Get all unlabeled examples."""
        return [ex for ex in self.iterate() if not ex.get("labeled")]

    def count(self) -> int:
        """Count total examples."""
        return sum(1 for _ in self.iterate())

    def count_labeled(self) -> int:
        """Count labeled examples."""
        return sum(1 for ex in self.iterate() if ex.get("labeled"))

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        return {
            **self.stats,
            "agent": self.agent_name,
            "file_path": str(self.file_path),
            "file_exists": self.file_path.exists(),
            "total_examples": self.count(),
            "labeled_examples": self.count_labeled(),
        }

    def export_for_training(
        self,
        output_path: str,
        labeled_only: bool = True
    ) -> int:
        """
        Export examples for training.

        Args:
            output_path: Path to export file
            labeled_only: Only export labeled examples

        Returns:
            Number of examples exported
        """
        examples = self.get_labeled() if labeled_only else list(self.iterate())

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(examples, f, indent=2)

        self.logger.info(f"Exported {len(examples)} examples to {output_path}")
        return len(examples)

    def clear(self) -> None:
        """Clear all stored examples."""
        with self._lock:
            if self.file_path.exists():
                self.file_path.unlink()
            self.stats = {
                "examples_stored": 0,
                "examples_labeled": 0,
                "last_write": None,
            }
            self.logger.info("Cleared all examples")
