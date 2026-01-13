"""
Unit tests for the EventBus implementation.

Run with: python -m pytest soc_core/events/test_bus.py -v
"""

import unittest
from bus import EventBus


class TestEventBusSubscribe(unittest.TestCase):
    """Tests for subscribe functionality."""

    def setUp(self):
        self.bus = EventBus()

    def test_subscribe_single_handler(self):
        """A single handler can be registered."""
        handler = lambda e: None
        self.bus.subscribe("AlertDetected", handler)

        self.assertTrue(self.bus.has_subscribers("AlertDetected"))
        self.assertEqual(self.bus.subscriber_count("AlertDetected"), 1)

    def test_subscribe_multiple_handlers_same_event(self):
        """Multiple handlers can subscribe to the same event type."""
        handler1 = lambda e: None
        handler2 = lambda e: None

        self.bus.subscribe("AlertDetected", handler1)
        self.bus.subscribe("AlertDetected", handler2)

        self.assertEqual(self.bus.subscriber_count("AlertDetected"), 2)

    def test_subscribe_handlers_different_events(self):
        """Handlers can subscribe to different event types."""
        handler1 = lambda e: None
        handler2 = lambda e: None

        self.bus.subscribe("AlertDetected", handler1)
        self.bus.subscribe("AnalysisCompleted", handler2)

        self.assertEqual(self.bus.subscriber_count("AlertDetected"), 1)
        self.assertEqual(self.bus.subscriber_count("AnalysisCompleted"), 1)

    def test_subscribe_non_callable_raises_error(self):
        """Subscribing with a non-callable raises TypeError."""
        with self.assertRaises(TypeError) as ctx:
            self.bus.subscribe("AlertDetected", "not a function")

        self.assertIn("callable", str(ctx.exception))

    def test_has_subscribers_returns_false_for_unknown_event(self):
        """has_subscribers returns False for event types with no handlers."""
        self.assertFalse(self.bus.has_subscribers("UnknownEvent"))

    def test_subscriber_count_returns_zero_for_unknown_event(self):
        """subscriber_count returns 0 for event types with no handlers."""
        self.assertEqual(self.bus.subscriber_count("UnknownEvent"), 0)


class TestEventBusPublish(unittest.TestCase):
    """Tests for publish functionality."""

    def setUp(self):
        self.bus = EventBus()
        self.received_events = []

    def test_publish_calls_handler(self):
        """Published events are received by handlers."""
        def handler(event):
            self.received_events.append(event)

        self.bus.subscribe("AlertDetected", handler)
        self.bus.publish("AlertDetected", {"event_id": "123"})

        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0]["event_id"], "123")

    def test_publish_calls_multiple_handlers(self):
        """Published events are received by all registered handlers."""
        results = []

        def handler1(event):
            results.append("handler1")

        def handler2(event):
            results.append("handler2")

        self.bus.subscribe("AlertDetected", handler1)
        self.bus.subscribe("AlertDetected", handler2)
        self.bus.publish("AlertDetected", {"event_id": "123"})

        self.assertEqual(results, ["handler1", "handler2"])

    def test_publish_handlers_called_in_order(self):
        """Handlers are called in registration order."""
        order = []

        for i in range(5):
            self.bus.subscribe("AlertDetected", lambda e, i=i: order.append(i))

        self.bus.publish("AlertDetected", {})

        self.assertEqual(order, [0, 1, 2, 3, 4])

    def test_publish_returns_handler_count(self):
        """Publish returns the number of handlers called."""
        self.bus.subscribe("AlertDetected", lambda e: None)
        self.bus.subscribe("AlertDetected", lambda e: None)

        count = self.bus.publish("AlertDetected", {})

        self.assertEqual(count, 2)

    def test_publish_no_handlers_returns_zero(self):
        """Publish to event with no handlers returns 0."""
        count = self.bus.publish("UnknownEvent", {})

        self.assertEqual(count, 0)

    def test_publish_non_dict_raises_error(self):
        """Publishing a non-dict event raises TypeError."""
        self.bus.subscribe("AlertDetected", lambda e: None)

        with self.assertRaises(TypeError) as ctx:
            self.bus.publish("AlertDetected", "not a dict")

        self.assertIn("dict", str(ctx.exception))

    def test_publish_only_calls_matching_handlers(self):
        """Only handlers for the published event type are called."""
        alert_received = []
        analysis_received = []

        self.bus.subscribe("AlertDetected", lambda e: alert_received.append(e))
        self.bus.subscribe("AnalysisCompleted", lambda e: analysis_received.append(e))

        self.bus.publish("AlertDetected", {"type": "alert"})

        self.assertEqual(len(alert_received), 1)
        self.assertEqual(len(analysis_received), 0)

    def test_publish_handler_exception_propagates(self):
        """Exceptions in handlers propagate to caller."""
        def failing_handler(event):
            raise ValueError("Handler failed")

        self.bus.subscribe("AlertDetected", failing_handler)

        with self.assertRaises(ValueError) as ctx:
            self.bus.publish("AlertDetected", {})

        self.assertIn("Handler failed", str(ctx.exception))

    def test_publish_exception_stops_subsequent_handlers(self):
        """When a handler raises, subsequent handlers are not called."""
        results = []

        def handler1(event):
            results.append("handler1")

        def handler2(event):
            raise ValueError("fail")

        def handler3(event):
            results.append("handler3")

        self.bus.subscribe("AlertDetected", handler1)
        self.bus.subscribe("AlertDetected", handler2)
        self.bus.subscribe("AlertDetected", handler3)

        with self.assertRaises(ValueError):
            self.bus.publish("AlertDetected", {})

        self.assertEqual(results, ["handler1"])


class TestEventBusUnsubscribe(unittest.TestCase):
    """Tests for unsubscribe functionality."""

    def setUp(self):
        self.bus = EventBus()

    def test_unsubscribe_removes_handler(self):
        """Unsubscribe removes the handler."""
        handler = lambda e: None
        self.bus.subscribe("AlertDetected", handler)

        result = self.bus.unsubscribe("AlertDetected", handler)

        self.assertTrue(result)
        self.assertFalse(self.bus.has_subscribers("AlertDetected"))

    def test_unsubscribe_returns_false_for_unknown_handler(self):
        """Unsubscribe returns False if handler wasn't registered."""
        handler = lambda e: None

        result = self.bus.unsubscribe("AlertDetected", handler)

        self.assertFalse(result)

    def test_unsubscribe_returns_false_for_unknown_event(self):
        """Unsubscribe returns False for unknown event types."""
        handler = lambda e: None

        result = self.bus.unsubscribe("UnknownEvent", handler)

        self.assertFalse(result)

    def test_unsubscribe_only_removes_specific_handler(self):
        """Unsubscribe only removes the specified handler."""
        handler1 = lambda e: None
        handler2 = lambda e: None

        self.bus.subscribe("AlertDetected", handler1)
        self.bus.subscribe("AlertDetected", handler2)
        self.bus.unsubscribe("AlertDetected", handler1)

        self.assertEqual(self.bus.subscriber_count("AlertDetected"), 1)

    def test_unsubscribed_handler_not_called(self):
        """Unsubscribed handlers are not called on publish."""
        results = []
        handler = lambda e: results.append("called")

        self.bus.subscribe("AlertDetected", handler)
        self.bus.unsubscribe("AlertDetected", handler)
        self.bus.publish("AlertDetected", {})

        self.assertEqual(results, [])


class TestEventBusClear(unittest.TestCase):
    """Tests for clear functionality."""

    def setUp(self):
        self.bus = EventBus()

    def test_clear_specific_event_type(self):
        """Clear removes all handlers for a specific event type."""
        self.bus.subscribe("AlertDetected", lambda e: None)
        self.bus.subscribe("AlertDetected", lambda e: None)
        self.bus.subscribe("AnalysisCompleted", lambda e: None)

        self.bus.clear("AlertDetected")

        self.assertFalse(self.bus.has_subscribers("AlertDetected"))
        self.assertTrue(self.bus.has_subscribers("AnalysisCompleted"))

    def test_clear_all_handlers(self):
        """Clear with no argument removes all handlers."""
        self.bus.subscribe("AlertDetected", lambda e: None)
        self.bus.subscribe("AnalysisCompleted", lambda e: None)
        self.bus.subscribe("RemediationProposed", lambda e: None)

        self.bus.clear()

        self.assertFalse(self.bus.has_subscribers("AlertDetected"))
        self.assertFalse(self.bus.has_subscribers("AnalysisCompleted"))
        self.assertFalse(self.bus.has_subscribers("RemediationProposed"))

    def test_clear_unknown_event_no_error(self):
        """Clear on unknown event type does not raise."""
        self.bus.clear("UnknownEvent")  # Should not raise


class TestEventBusIntegration(unittest.TestCase):
    """Integration tests simulating real usage patterns."""

    def setUp(self):
        self.bus = EventBus()

    def test_full_event_flow(self):
        """Simulate a complete event flow through the bus."""
        events_log = []

        # Simulate SOC Analyst subscribing to alerts
        def analyst_handler(event):
            events_log.append({
                "receiver": "analyst",
                "event_id": event["event_id"]
            })

        # Simulate Remediator subscribing to analysis results
        def remediator_handler(event):
            events_log.append({
                "receiver": "remediator",
                "event_id": event["event_id"]
            })

        self.bus.subscribe("AlertDetected", analyst_handler)
        self.bus.subscribe("AnalysisCompleted", remediator_handler)

        # SOC Builder publishes an alert
        self.bus.publish("AlertDetected", {
            "event_id": "alert-001",
            "correlation_id": "corr-001",
            "timestamp": "2025-01-01T00:00:00Z",
            "producer": "soc_builder",
            "payload": {"severity": "high"}
        })

        # Analyst publishes analysis result
        self.bus.publish("AnalysisCompleted", {
            "event_id": "analysis-001",
            "correlation_id": "corr-001",
            "timestamp": "2025-01-01T00:00:01Z",
            "producer": "soc_analyst",
            "payload": {"verdict": "true_positive"}
        })

        self.assertEqual(len(events_log), 2)
        self.assertEqual(events_log[0]["receiver"], "analyst")
        self.assertEqual(events_log[0]["event_id"], "alert-001")
        self.assertEqual(events_log[1]["receiver"], "remediator")
        self.assertEqual(events_log[1]["event_id"], "analysis-001")


if __name__ == "__main__":
    unittest.main()
