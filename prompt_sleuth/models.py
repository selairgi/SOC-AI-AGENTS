"""
Data models for PromptSleuth.
Defines the core data structures used throughout the system.
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Literal
from datetime import datetime
import json


RelationType = Literal["related", "unrelated", "uncertain"]


@dataclass
class Task:
    """Represents a single task extracted from a prompt."""
    id: str
    text: str  # 2-5 word concise description
    source: Literal["parent", "child"]  # from system_prompt or user_input
    confidence: float = 1.0

    def normalize(self) -> str:
        """Normalize task text (lowercase, trim, remove noise)."""
        return " ".join(self.text.lower().strip().split())

    def __hash__(self):
        return hash((self.id, self.normalize()))

    def __eq__(self, other):
        if not isinstance(other, Task):
            return False
        return self.normalize() == other.normalize()


@dataclass
class TaskRelation:
    """Represents a relationship between a parent and child task."""
    parent_task: Task
    child_task: Task
    relation: RelationType
    confidence: float  # 0.0 to 1.0
    explanation: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "parent": self.parent_task.text,
            "child": self.child_task.text,
            "relation": self.relation,
            "confidence": self.confidence,
            "explanation": self.explanation
        }


@dataclass
class TaskGraph:
    """Graph structure containing tasks and their relationships."""
    parent_tasks: List[Task] = field(default_factory=list)
    child_tasks: List[Task] = field(default_factory=list)
    relations: List[TaskRelation] = field(default_factory=list)

    def add_relation(self, relation: TaskRelation):
        """Add a relation to the graph."""
        self.relations.append(relation)

    def get_relations_for_child(self, child_task: Task) -> List[TaskRelation]:
        """Get all relations involving a specific child task."""
        return [r for r in self.relations if r.child_task == child_task]

    def get_unrelated_children(self, uncertain_threshold: float = 0.6) -> List[Task]:
        """
        Find child tasks that are unrelated to all parent tasks.
        A child is considered unrelated if all its relations are 'unrelated'
        or 'uncertain' with low confidence.
        """
        unrelated = []

        for child in self.child_tasks:
            child_relations = self.get_relations_for_child(child)

            if not child_relations:
                continue

            # Check if all relations are unrelated or uncertain with low confidence
            all_unrelated = True
            for rel in child_relations:
                if rel.relation == "related":
                    all_unrelated = False
                    break
                elif rel.relation == "uncertain" and rel.confidence >= uncertain_threshold:
                    all_unrelated = False
                    break

            if all_unrelated:
                unrelated.append(child)

        return unrelated

    def to_dict(self) -> dict:
        """Convert graph to dictionary format."""
        return {
            "parent_tasks": [t.text for t in self.parent_tasks],
            "child_tasks": [t.text for t in self.child_tasks],
            "relations": [r.to_dict() for r in self.relations]
        }


@dataclass
class DetectionResult:
    """Result of prompt injection detection."""
    is_injection: bool
    tasks_parent: List[str]
    tasks_child: List[str]
    relations: List[dict]
    suspicious_tasks: List[str] = field(default_factory=list)
    explanation: Optional[str] = None
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON serialization."""
        return {
            "is_injection": self.is_injection,
            "tasks_parent": self.tasks_parent,
            "tasks_child": self.tasks_child,
            "relations": self.relations,
            "suspicious_tasks": self.suspicious_tasks,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class PromptInput:
    """Input data structure for prompt analysis."""
    system_prompt: str
    user_input: str
    metadata: Optional[dict] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
