"""
Unit tests for RiskAgent.

Run with: python -m pytest soc_core/agents/test_risk_agent.py -v
"""

import unittest
import uuid
from datetime import datetime, timezone

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from events.bus import EventBus
from agents.risk_agent import RiskAgent


class TestRiskAgentLifecycle(unittest.TestCase):
    """Tests for agent start/stop lifecycle."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)

    def tearDown(self):
        if self.agent.is_running():
            self.agent.stop()

    def test_start_subscribes_to_both_events(self):
        """Starting the agent subscribes to AnalysisCompleted and ContextEnriched."""
        self.agent.start()

        self.assertTrue(self.agent.is_running())
        self.assertTrue(self.bus.has_subscribers("AnalysisCompleted"))
        self.assertTrue(self.bus.has_subscribers("ContextEnriched"))

    def test_stop_unsubscribes_from_all_events(self):
        """Stopping the agent unsubscribes from all events."""
        self.agent.start()
        self.agent.stop()

        self.assertFalse(self.agent.is_running())
        self.assertFalse(self.bus.has_subscribers("AnalysisCompleted"))
        self.assertFalse(self.bus.has_subscribers("ContextEnriched"))

    def test_start_when_already_running(self):
        """Starting an already running agent is safe."""
        self.agent.start()
        self.agent.start()  # Should not raise

        self.assertTrue(self.agent.is_running())
        self.assertEqual(self.bus.subscriber_count("AnalysisCompleted"), 1)
        self.assertEqual(self.bus.subscriber_count("ContextEnriched"), 1)

    def test_stop_when_not_running(self):
        """Stopping an agent that isn't running is safe."""
        self.agent.stop()  # Should not raise
        self.assertFalse(self.agent.is_running())


class TestRiskAgentAnalysisCompleted(unittest.TestCase):
    """Tests for processing AnalysisCompleted events."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)
        self.assessments = []

        def capture_assessments(event):
            self.assessments.append(event)

        self.bus.subscribe("RiskAssessment", capture_assessments)
        self.agent.start()

    def tearDown(self):
        self.agent.stop()

    def _create_analysis_event(
        self,
        severity: str = "high",
        threat_type: str = "prompt_injection",
        certainty_score: float = 0.8,
        verdict: str = "true_positive"
    ) -> dict:
        return {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "soc_analyst",
            "payload": {
                "alert_id": f"alert-{uuid.uuid4().hex[:8]}",
                "analysis_id": f"analysis-{uuid.uuid4().hex[:8]}",
                "verdict": verdict,
                "certainty_score": certainty_score,
                "severity": severity,
                "threat_type": threat_type
            }
        }

    def test_publishes_risk_assessment(self):
        """Processing AnalysisCompleted publishes RiskAssessment."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        self.assertEqual(len(self.assessments), 1)

    def test_assessment_has_required_fields(self):
        """RiskAssessment has all required fields."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        assessment = self.assessments[0]
        self.assertIn("event_id", assessment)
        self.assertIn("correlation_id", assessment)
        self.assertIn("timestamp", assessment)
        self.assertIn("producer", assessment)
        self.assertIn("payload", assessment)

    def test_assessment_payload_has_risk_scores(self):
        """Assessment payload contains risk_scores."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        payload = self.assessments[0]["payload"]
        self.assertIn("risk_scores", payload)

        scores = payload["risk_scores"]
        self.assertIn("technical_severity", scores)
        self.assertIn("business_impact", scores)
        self.assertIn("blast_radius", scores)

    def test_technical_severity_values(self):
        """technical_severity is one of low/medium/high."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        scores = self.assessments[0]["payload"]["risk_scores"]
        self.assertIn(scores["technical_severity"], ["low", "medium", "high"])

    def test_business_impact_values(self):
        """business_impact is one of low/medium/high."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        scores = self.assessments[0]["payload"]["risk_scores"]
        self.assertIn(scores["business_impact"], ["low", "medium", "high"])

    def test_blast_radius_values(self):
        """blast_radius is one of single_user/team/org."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        scores = self.assessments[0]["payload"]["risk_scores"]
        self.assertIn(scores["blast_radius"], ["single_user", "team", "org"])

    def test_overall_risk_level(self):
        """Assessment includes overall_risk_level."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        payload = self.assessments[0]["payload"]
        self.assertIn("overall_risk_level", payload)
        self.assertIn(payload["overall_risk_level"], ["low", "medium", "high", "critical"])

    def test_source_event_type_is_analysis(self):
        """source_event_type is AnalysisCompleted."""
        event = self._create_analysis_event()
        self.bus.publish("AnalysisCompleted", event)

        payload = self.assessments[0]["payload"]
        self.assertEqual(payload["source_event_type"], "AnalysisCompleted")

    def test_high_severity_high_risk(self):
        """High severity threats get higher technical severity."""
        low_event = self._create_analysis_event(severity="low", certainty_score=0.5)
        high_event = self._create_analysis_event(severity="critical", certainty_score=0.95)

        self.bus.publish("AnalysisCompleted", low_event)
        self.bus.publish("AnalysisCompleted", high_event)

        low_tech = self.assessments[0]["payload"]["risk_scores"]["technical_severity"]
        high_tech = self.assessments[1]["payload"]["risk_scores"]["technical_severity"]

        severity_order = {"low": 1, "medium": 2, "high": 3}
        self.assertGreaterEqual(severity_order[high_tech], severity_order[low_tech])

    def test_data_exfiltration_high_business_impact(self):
        """Data exfiltration has higher business impact."""
        event = self._create_analysis_event(
            threat_type="data_exfiltration",
            severity="high"
        )
        self.bus.publish("AnalysisCompleted", event)

        impact = self.assessments[0]["payload"]["risk_scores"]["business_impact"]
        # Data exfiltration should not be low impact
        self.assertIn(impact, ["medium", "high"])


class TestRiskAgentContextEnriched(unittest.TestCase):
    """Tests for processing ContextEnriched events."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)
        self.assessments = []

        def capture_assessments(event):
            self.assessments.append(event)

        self.bus.subscribe("RiskAssessment", capture_assessments)
        self.agent.start()

    def tearDown(self):
        self.agent.stop()

    def _create_context_event(
        self,
        similar_alert_count: int = 1,
        is_escalating: bool = False,
        threat_types: list = None,
        max_severity: str = "high",
        agent_ids: list = None,
        user_ids: list = None,
        src_ips: list = None
    ) -> dict:
        threat_types = threat_types or ["prompt_injection"]
        agent_ids = agent_ids or ["agent_001"]
        user_ids = user_ids or ["user_001"]
        src_ips = src_ips or ["192.168.1.100"]

        return {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "context_agent",
            "payload": {
                "alert_id": f"alert-{uuid.uuid4().hex[:8]}",
                "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                "original_alert": {
                    "severity": max_severity,
                    "threat_type": threat_types[0] if threat_types else "unknown",
                    "confidence": 0.85
                },
                "context": {
                    "similar_alert_count": similar_alert_count,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "is_new_incident": similar_alert_count == 1,
                    "is_escalating": is_escalating,
                    "threat_types_seen": threat_types,
                    "sources_involved": {
                        "agent_ids": agent_ids,
                        "user_ids": user_ids,
                        "src_ips": src_ips
                    },
                    "max_severity": max_severity
                }
            }
        }

    def test_publishes_risk_assessment(self):
        """Processing ContextEnriched publishes RiskAssessment."""
        event = self._create_context_event()
        self.bus.publish("ContextEnriched", event)

        self.assertEqual(len(self.assessments), 1)

    def test_source_event_type_is_context(self):
        """source_event_type is ContextEnriched."""
        event = self._create_context_event()
        self.bus.publish("ContextEnriched", event)

        payload = self.assessments[0]["payload"]
        self.assertEqual(payload["source_event_type"], "ContextEnriched")

    def test_escalating_increases_risk(self):
        """Escalating incidents get higher risk scores."""
        normal_event = self._create_context_event(is_escalating=False)
        escalating_event = self._create_context_event(is_escalating=True, similar_alert_count=5)

        self.bus.publish("ContextEnriched", normal_event)
        self.bus.publish("ContextEnriched", escalating_event)

        normal_score = self.assessments[0]["payload"]["risk_score_numeric"]
        escalating_score = self.assessments[1]["payload"]["risk_score_numeric"]

        self.assertGreater(escalating_score, normal_score)

    def test_multiple_users_team_blast_radius(self):
        """Multiple affected users increase blast radius."""
        single_user = self._create_context_event(user_ids=["user_001"])
        multi_user = self._create_context_event(
            user_ids=["user_001", "user_002", "user_003"]
        )

        self.bus.publish("ContextEnriched", single_user)
        self.bus.publish("ContextEnriched", multi_user)

        single_radius = self.assessments[0]["payload"]["risk_scores"]["blast_radius"]
        multi_radius = self.assessments[1]["payload"]["risk_scores"]["blast_radius"]

        radius_order = {"single_user": 1, "team": 2, "org": 3}
        self.assertGreaterEqual(radius_order[multi_radius], radius_order[single_radius])

    def test_many_alerts_org_blast_radius(self):
        """Many similar alerts indicate org-wide blast radius."""
        event = self._create_context_event(
            similar_alert_count=15,
            user_ids=["u1", "u2", "u3", "u4", "u5"]
        )
        self.bus.publish("ContextEnriched", event)

        radius = self.assessments[0]["payload"]["risk_scores"]["blast_radius"]
        self.assertEqual(radius, "org")

    def test_incident_id_included(self):
        """incident_id is included from ContextEnriched."""
        event = self._create_context_event()
        self.bus.publish("ContextEnriched", event)

        payload = self.assessments[0]["payload"]
        self.assertIsNotNone(payload.get("incident_id"))


class TestRiskAgentRiskCalculation(unittest.TestCase):
    """Tests for risk calculation logic."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)
        self.assessments = []

        self.bus.subscribe("RiskAssessment", lambda e: self.assessments.append(e))
        self.agent.start()

    def tearDown(self):
        self.agent.stop()

    def test_critical_risk_for_severe_threats(self):
        """Critical severity + high confidence = critical overall risk."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "context_agent",
            "payload": {
                "alert_id": "alert-001",
                "incident_id": "inc-001",
                "original_alert": {
                    "severity": "critical",
                    "threat_type": "data_exfiltration",
                    "confidence": 0.95
                },
                "context": {
                    "similar_alert_count": 10,
                    "is_escalating": True,
                    "threat_types_seen": ["data_exfiltration"],
                    "sources_involved": {
                        "agent_ids": ["a1", "a2"],
                        "user_ids": ["u1", "u2", "u3"],
                        "src_ips": ["1.1.1.1", "2.2.2.2"]
                    },
                    "max_severity": "critical"
                }
            }
        }
        self.bus.publish("ContextEnriched", event)

        risk_level = self.assessments[0]["payload"]["overall_risk_level"]
        self.assertIn(risk_level, ["high", "critical"])

    def test_low_risk_for_minor_threats(self):
        """Low severity + low confidence = low overall risk."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "soc_analyst",
            "payload": {
                "alert_id": "alert-001",
                "verdict": "false_positive",
                "certainty_score": 0.3,
                "severity": "low",
                "threat_type": "rate_limit_abuse"
            }
        }
        self.bus.publish("AnalysisCompleted", event)

        risk_level = self.assessments[0]["payload"]["overall_risk_level"]
        self.assertEqual(risk_level, "low")

    def test_numeric_score_in_range(self):
        """Numeric score is between 0 and 100."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "soc_analyst",
            "payload": {
                "alert_id": "alert-001",
                "verdict": "true_positive",
                "certainty_score": 0.75,
                "severity": "medium",
                "threat_type": "prompt_injection"
            }
        }
        self.bus.publish("AnalysisCompleted", event)

        score = self.assessments[0]["payload"]["risk_score_numeric"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


class TestRiskAgentRecommendations(unittest.TestCase):
    """Tests for recommendation generation."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)
        self.assessments = []

        self.bus.subscribe("RiskAssessment", lambda e: self.assessments.append(e))
        self.agent.start()

    def tearDown(self):
        self.agent.stop()

    def test_recommendations_included(self):
        """Recommendations are included in assessment."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "soc_analyst",
            "payload": {
                "alert_id": "alert-001",
                "severity": "high",
                "threat_type": "prompt_injection"
            }
        }
        self.bus.publish("AnalysisCompleted", event)

        recommendations = self.assessments[0]["payload"].get("recommendations")
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)

    def test_data_exfiltration_specific_recommendations(self):
        """Data exfiltration gets specific recommendations."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "soc_analyst",
            "payload": {
                "alert_id": "alert-001",
                "severity": "critical",
                "threat_type": "data_exfiltration"
            }
        }
        self.bus.publish("AnalysisCompleted", event)

        recommendations = self.assessments[0]["payload"]["recommendations"]
        recommendations_text = " ".join(recommendations).lower()

        self.assertTrue(
            "data" in recommendations_text or "access" in recommendations_text,
            "Expected data-related recommendations"
        )


class TestRiskAgentStatistics(unittest.TestCase):
    """Tests for statistics tracking."""

    def setUp(self):
        self.bus = EventBus()
        self.agent = RiskAgent(self.bus)
        self.agent.start()

    def tearDown(self):
        self.agent.stop()

    def test_analysis_events_counter(self):
        """Counts AnalysisCompleted events."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "test",
            "payload": {"severity": "medium", "threat_type": "test"}
        }

        self.bus.publish("AnalysisCompleted", event)
        self.bus.publish("AnalysisCompleted", event)

        self.assertEqual(self.agent.stats["analysis_events_received"], 2)

    def test_context_events_counter(self):
        """Counts ContextEnriched events."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "test",
            "payload": {
                "original_alert": {"severity": "medium"},
                "context": {
                    "similar_alert_count": 1,
                    "sources_involved": {}
                }
            }
        }

        self.bus.publish("ContextEnriched", event)

        self.assertEqual(self.agent.stats["context_events_received"], 1)

    def test_risk_levels_tracking(self):
        """Tracks count of each risk level."""
        # Low risk event
        low_event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "test",
            "payload": {
                "severity": "low",
                "threat_type": "rate_limit_abuse",
                "certainty_score": 0.3
            }
        }
        self.bus.publish("AnalysisCompleted", low_event)

        stats = self.agent.get_stats()
        total_levels = sum(stats["risk_levels"].values())
        self.assertEqual(total_levels, 1)


class TestRiskAgentIndependence(unittest.TestCase):
    """Tests to verify agent works independently."""

    def test_processes_analysis_without_context(self):
        """Can process AnalysisCompleted without ContextAgent."""
        bus = EventBus()
        risk_agent = RiskAgent(bus)
        risk_agent.start()

        assessments = []
        bus.subscribe("RiskAssessment", lambda e: assessments.append(e))

        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "test",
            "payload": {
                "alert_id": "alert-001",
                "severity": "high",
                "threat_type": "prompt_injection"
            }
        }
        bus.publish("AnalysisCompleted", event)

        risk_agent.stop()

        self.assertEqual(len(assessments), 1)

    def test_processes_context_without_analysis(self):
        """Can process ContextEnriched without AnalysisCompleted."""
        bus = EventBus()
        risk_agent = RiskAgent(bus)
        risk_agent.start()

        assessments = []
        bus.subscribe("RiskAssessment", lambda e: assessments.append(e))

        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "context_agent",
            "payload": {
                "alert_id": "alert-001",
                "incident_id": "inc-001",
                "original_alert": {"severity": "medium"},
                "context": {
                    "similar_alert_count": 3,
                    "is_escalating": False,
                    "sources_involved": {}
                }
            }
        }
        bus.publish("ContextEnriched", event)

        risk_agent.stop()

        self.assertEqual(len(assessments), 1)

    def test_correlation_id_preserved(self):
        """Correlation ID is preserved from source event."""
        bus = EventBus()
        risk_agent = RiskAgent(bus)
        risk_agent.start()

        assessments = []
        bus.subscribe("RiskAssessment", lambda e: assessments.append(e))

        correlation_id = "test-corr-12345"
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": correlation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "test",
            "payload": {"severity": "medium", "threat_type": "test"}
        }
        bus.publish("AnalysisCompleted", event)

        risk_agent.stop()

        self.assertEqual(assessments[0]["correlation_id"], correlation_id)


if __name__ == "__main__":
    unittest.main()
