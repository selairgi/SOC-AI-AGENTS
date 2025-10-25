"""
Message bus for SOC AI Agents communication.
"""

import asyncio
from config import ALERT_QUEUE_MAX
from models import Alert


class MessageBus:
    def __init__(self):
        self.alert_queue = asyncio.Queue(maxsize=ALERT_QUEUE_MAX)

    async def publish_alert(self, alert: Alert):
        await self.alert_queue.put(alert)

    async def subscribe_alerts(self):
        while True:
            alert = await self.alert_queue.get()
            yield alert

