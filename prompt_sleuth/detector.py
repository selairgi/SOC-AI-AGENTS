"""
Injection Detector for PromptSleuth.
Analyzes task graph to detect prompt injections (Step E).
"""

from typing import List, Optional
from .models import TaskGraph, DetectionResult, Task
from .config import PromptSleuthConfig


class InjectionDetector:
    """
    Detects prompt injections by analyzing task relationship graph.
    Uses clustering and relation analysis to identify suspicious tasks.
    """

    def __init__(self, config: PromptSleuthConfig):
        self.config = config

    def detect(self, graph: TaskGraph) -> DetectionResult:
        """
        Detect prompt injection from task graph.

        Args:
            graph: Task relationship graph

        Returns:
            Detection result
        """
        # Handle empty graph
        if not graph.child_tasks or not graph.parent_tasks:
            return DetectionResult(
                is_injection=False,
                tasks_parent=[t.text for t in graph.parent_tasks],
                tasks_child=[t.text for t in graph.child_tasks],
                relations=[],
                explanation="No tasks to analyze"
            )

        # Analyze graph for suspicious patterns
        suspicious_tasks = self._identify_suspicious_tasks(graph)

        # Calculate overall confidence
        confidence = self._calculate_confidence(graph, suspicious_tasks)

        # Determine if injection detected
        is_injection = len(suspicious_tasks) > 0 and confidence >= self.config.detection.min_injection_confidence

        # Build explanation
        explanation = self._build_explanation(graph, suspicious_tasks, is_injection)

        # Check for high uncertainty (may need human review)
        uncertain_proportion = self._calculate_uncertain_proportion(graph)
        needs_review = uncertain_proportion > self.config.detection.uncertain_proportion_threshold

        metadata = {
            "uncertain_proportion": uncertain_proportion,
            "needs_human_review": needs_review,
            "total_relations": len(graph.relations),
            "suspicious_count": len(suspicious_tasks)
        }

        return DetectionResult(
            is_injection=is_injection,
            tasks_parent=[t.text for t in graph.parent_tasks],
            tasks_child=[t.text for t in graph.child_tasks],
            relations=[r.to_dict() for r in graph.relations],
            suspicious_tasks=[t.text for t in suspicious_tasks],
            explanation=explanation,
            confidence=confidence,
            metadata=metadata
        )

    def _identify_suspicious_tasks(self, graph: TaskGraph) -> List[Task]:
        """
        Identify child tasks that are suspicious (unrelated to all parents).

        Args:
            graph: Task graph

        Returns:
            List of suspicious child tasks
        """
        suspicious = []

        for child in graph.child_tasks:
            if self._is_task_suspicious(child, graph):
                suspicious.append(child)

        return suspicious

    def _is_task_suspicious(self, child: Task, graph: TaskGraph) -> bool:
        """
        Check if a child task is suspicious.

        A task is suspicious if ALL its relations to parent tasks are:
        - 'unrelated', OR
        - 'uncertain' with low confidence

        Args:
            child: Child task to check
            graph: Task graph

        Returns:
            True if suspicious, False otherwise
        """
        relations = graph.get_relations_for_child(child)

        if not relations:
            # No relations = suspicious (orphaned task)
            return True

        # Check if ALL relations are unrelated/uncertain
        for relation in relations:
            if relation.relation == "related":
                # Found a related relation = not suspicious
                return False

            if relation.relation == "uncertain":
                # If uncertain with high confidence, treat as potentially related
                if relation.confidence >= self.config.detection.uncertain_threshold:
                    return False

        # All relations are unrelated or uncertain with low confidence
        return True

    def _calculate_confidence(self, graph: TaskGraph, suspicious_tasks: List[Task]) -> float:
        """
        Calculate overall detection confidence.

        Args:
            graph: Task graph
            suspicious_tasks: List of suspicious tasks

        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not suspicious_tasks:
            return 0.0

        if not graph.relations:
            return 0.5  # Low confidence if no relations

        # Calculate based on:
        # 1. Proportion of suspicious tasks
        # 2. Confidence of unrelated relations
        # 3. Strength of evidence

        suspicious_ratio = len(suspicious_tasks) / len(graph.child_tasks)

        # Get all relations for suspicious tasks
        suspicious_relations = []
        for task in suspicious_tasks:
            suspicious_relations.extend(graph.get_relations_for_child(task))

        if not suspicious_relations:
            return 0.5

        # Average confidence of unrelated/uncertain relations
        avg_relation_confidence = sum(r.confidence for r in suspicious_relations) / len(suspicious_relations)

        # Combined confidence (weighted)
        confidence = (suspicious_ratio * 0.4 + avg_relation_confidence * 0.6)

        return min(1.0, max(0.0, confidence))

    def _calculate_uncertain_proportion(self, graph: TaskGraph) -> float:
        """
        Calculate proportion of uncertain relations.

        Args:
            graph: Task graph

        Returns:
            Proportion of uncertain relations (0.0 to 1.0)
        """
        if not graph.relations:
            return 0.0

        uncertain_count = sum(1 for r in graph.relations if r.relation == "uncertain")
        return uncertain_count / len(graph.relations)

    def _build_explanation(
        self,
        graph: TaskGraph,
        suspicious_tasks: List[Task],
        is_injection: bool
    ) -> str:
        """
        Build human-readable explanation of detection result.

        Args:
            graph: Task graph
            suspicious_tasks: List of suspicious tasks
            is_injection: Whether injection was detected

        Returns:
            Explanation string
        """
        if not is_injection:
            if not suspicious_tasks:
                return "All child tasks are related to parent tasks. No injection detected."
            else:
                return f"Found {len(suspicious_tasks)} potentially suspicious task(s), but confidence below threshold."

        # Build detailed explanation for injection
        parts = [f"Detected {len(suspicious_tasks)} suspicious task(s):"]

        for task in suspicious_tasks[:3]:  # Limit to first 3 for brevity
            relations = graph.get_relations_for_child(task)

            # Summarize relations
            relation_summary = []
            for rel in relations:
                if rel.explanation and self.config.detection.enable_explanations:
                    relation_summary.append(
                        f"  - vs '{rel.parent_task.text}': {rel.relation} ({rel.explanation[:50]}...)"
                    )
                else:
                    relation_summary.append(
                        f"  - vs '{rel.parent_task.text}': {rel.relation}"
                    )

            parts.append(f"\n'{task.text}':")
            parts.extend(relation_summary[:2])  # Limit relations shown

        if len(suspicious_tasks) > 3:
            parts.append(f"\n...and {len(suspicious_tasks) - 3} more suspicious task(s)")

        return "\n".join(parts)

    def cluster_related_tasks(self, graph: TaskGraph) -> List[List[Task]]:
        """
        Cluster child tasks by their parent relations.
        Tasks that are related to the same parents form a cluster.

        Args:
            graph: Task graph

        Returns:
            List of task clusters
        """
        clusters = []

        # Track which children have been clustered
        clustered = set()

        for child in graph.child_tasks:
            if child in clustered:
                continue

            # Find related parents for this child
            child_relations = graph.get_relations_for_child(child)
            related_parents = {
                r.parent_task for r in child_relations if r.relation == "related"
            }

            if not related_parents:
                # Orphan task (no related parents) = own cluster
                clusters.append([child])
                clustered.add(child)
                continue

            # Find other children related to same parents
            cluster = [child]
            clustered.add(child)

            for other_child in graph.child_tasks:
                if other_child in clustered:
                    continue

                other_relations = graph.get_relations_for_child(other_child)
                other_parents = {
                    r.parent_task for r in other_relations if r.relation == "related"
                }

                # Check overlap
                if related_parents & other_parents:
                    cluster.append(other_child)
                    clustered.add(other_child)

            clusters.append(cluster)

        return clusters
