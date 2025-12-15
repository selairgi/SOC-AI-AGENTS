"""
Bounded queue system with backpressure for SOC AI Agents.
Prevents memory exhaustion and provides controlled failure modes.
"""

import asyncio
import time
import logging
from typing import Any, Optional, Dict, List, Callable
from dataclasses import dataclass
from enum import Enum
import threading


class QueueStrategy(Enum):
    """Queue behavior when full."""
    BLOCK = "block"           # Block until space available
    DROP_OLDEST = "drop_oldest"  # Drop oldest items
    DROP_NEWEST = "drop_newest"  # Drop newest items
    REJECT = "reject"         # Reject new items immediately


@dataclass
class QueueConfig:
    """Configuration for bounded queue."""
    max_size: int = 1000
    strategy: QueueStrategy = QueueStrategy.BLOCK
    timeout: float = 5.0  # Timeout for put operations
    alert_threshold: float = 0.8  # Alert when queue is 80% full
    metrics_interval: float = 60.0  # Metrics collection interval


@dataclass
class QueueMetrics:
    """Metrics for queue performance."""
    current_size: int = 0
    max_size: int = 0
    total_puts: int = 0
    total_gets: int = 0
    total_drops: int = 0
    total_rejects: int = 0
    total_timeouts: int = 0
    avg_put_time: float = 0.0
    avg_get_time: float = 0.0
    utilization: float = 0.0
    last_alert_time: float = 0.0


class BoundedQueue:
    """Bounded queue with backpressure and metrics."""
    
    def __init__(self, config: QueueConfig = None, name: str = "default"):
        self.config = config or QueueConfig()
        self.name = name
        self.logger = logging.getLogger(f"BoundedQueue.{name}")
        
        # Queue implementation
        self._queue = asyncio.Queue(maxsize=self.config.max_size)
        self._lock = asyncio.Lock()
        
        # Metrics
        self.metrics = QueueMetrics(max_size=self.config.max_size)
        
        # Alert callback
        self._alert_callback: Optional[Callable] = None
        
        # Background tasks
        self._metrics_thread = None
        self._start_metrics_thread()

    def _start_metrics_thread(self):
        """Start background thread for metrics collection."""
        import threading
        import time

        def collect_metrics():
            while True:
                try:
                    self._update_metrics_sync()
                    time.sleep(self.config.metrics_interval)
                except Exception as e:
                    self.logger.error(f"Error in metrics thread: {e}")

        self._metrics_thread = threading.Thread(target=collect_metrics, daemon=True)
        self._metrics_thread.start()

    def _update_metrics_sync(self):
        """Update queue metrics (synchronous version)."""
        self.metrics.current_size = self._queue.qsize()
        if self.metrics.max_size > 0:
            self.metrics.utilization = self.metrics.current_size / self.metrics.max_size

        # Check for alerts (simplified, no async callback)
        if (self.metrics.utilization >= self.config.alert_threshold and
            time.time() - self.metrics.last_alert_time > 300):  # 5 minute cooldown
            self.logger.warning(
                f"Queue '{self.name}' saturation alert: {self.metrics.utilization:.1%} full"
            )
            self.metrics.last_alert_time = time.time()

    async def _update_metrics(self):
        """Update queue metrics."""
        async with self._lock:
            self.metrics.current_size = self._queue.qsize()
            self.metrics.utilization = self.metrics.current_size / self.metrics.max_size
            
            # Check for alerts
            if (self.metrics.utilization >= self.config.alert_threshold and 
                time.time() - self.metrics.last_alert_time > 300):  # 5 minute cooldown
                
                await self._trigger_alert()
                self.metrics.last_alert_time = time.time()
    
    async def _trigger_alert(self):
        """Trigger queue saturation alert."""
        if self._alert_callback:
            try:
                await self._alert_callback(self.name, self.metrics)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
        
        self.logger.warning(
            f"Queue {self.name} utilization high: {self.metrics.utilization:.1%} "
            f"({self.metrics.current_size}/{self.metrics.max_size})"
        )
    
    def set_alert_callback(self, callback: Callable[[str, QueueMetrics], None]):
        """Set callback for queue saturation alerts."""
        self._alert_callback = callback
    
    async def put(self, item: Any, timeout: Optional[float] = None) -> bool:
        """Put item in queue with backpressure handling."""
        start_time = time.time()
        timeout = timeout or self.config.timeout
        
        try:
            if self.config.strategy == QueueStrategy.BLOCK:
                await asyncio.wait_for(self._queue.put(item), timeout=timeout)
                self.metrics.total_puts += 1
                return True
                
            elif self.config.strategy == QueueStrategy.REJECT:
                if self._queue.full():
                    self.metrics.total_rejects += 1
                    self.logger.warning(f"Queue {self.name} full, rejecting item")
                    return False
                else:
                    await self._queue.put(item)
                    self.metrics.total_puts += 1
                    return True
                    
            elif self.config.strategy == QueueStrategy.DROP_OLDEST:
                if self._queue.full():
                    try:
                        # Remove oldest item
                        self._queue.get_nowait()
                        self.metrics.total_drops += 1
                    except asyncio.QueueEmpty:
                        pass
                
                await self._queue.put(item)
                self.metrics.total_puts += 1
                return True
                
            elif self.config.strategy == QueueStrategy.DROP_NEWEST:
                if self._queue.full():
                    self.metrics.total_drops += 1
                    self.logger.warning(f"Queue {self.name} full, dropping newest item")
                    return False
                else:
                    await self._queue.put(item)
                    self.metrics.total_puts += 1
                    return True
                    
        except asyncio.TimeoutError:
            self.metrics.total_timeouts += 1
            self.logger.warning(f"Queue {self.name} put timeout after {timeout}s")
            return False
        except Exception as e:
            self.logger.error(f"Error putting item in queue {self.name}: {e}")
            return False
        finally:
            # Update timing metrics
            put_time = time.time() - start_time
            self.metrics.avg_put_time = (
                (self.metrics.avg_put_time * (self.metrics.total_puts - 1) + put_time) /
                self.metrics.total_puts
            )
    
    async def get(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Get item from queue."""
        start_time = time.time()
        timeout = timeout or self.config.timeout
        
        try:
            item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            self.metrics.total_gets += 1
            return item
        except asyncio.TimeoutError:
            self.logger.warning(f"Queue {self.name} get timeout after {timeout}s")
            return None
        except Exception as e:
            self.logger.error(f"Error getting item from queue {self.name}: {e}")
            return None
        finally:
            # Update timing metrics
            get_time = time.time() - start_time
            if self.metrics.total_gets > 0:
                self.metrics.avg_get_time = (
                    (self.metrics.avg_get_time * (self.metrics.total_gets - 1) + get_time) /
                    self.metrics.total_gets
                )
    
    async def put_nowait(self, item: Any) -> bool:
        """Put item in queue without waiting."""
        try:
            if self.config.strategy == QueueStrategy.REJECT and self._queue.full():
                self.metrics.total_rejects += 1
                return False
            
            if self.config.strategy == QueueStrategy.DROP_OLDEST and self._queue.full():
                try:
                    self._queue.get_nowait()
                    self.metrics.total_drops += 1
                except asyncio.QueueEmpty:
                    pass
            
            self._queue.put_nowait(item)
            self.metrics.total_puts += 1
            return True
        except asyncio.QueueFull:
            if self.config.strategy == QueueStrategy.DROP_NEWEST:
                self.metrics.total_drops += 1
            return False
    
    def get_nowait(self) -> Optional[Any]:
        """Get item from queue without waiting."""
        try:
            item = self._queue.get_nowait()
            self.metrics.total_gets += 1
            return item
        except asyncio.QueueEmpty:
            return None
    
    def qsize(self) -> int:
        """Get current queue size."""
        return self._queue.qsize()
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue.empty()
    
    def full(self) -> bool:
        """Check if queue is full."""
        return self._queue.full()
    
    def get_metrics(self) -> QueueMetrics:
        """Get current queue metrics."""
        return QueueMetrics(
            current_size=self.metrics.current_size,
            max_size=self.metrics.max_size,
            total_puts=self.metrics.total_puts,
            total_gets=self.metrics.total_gets,
            total_drops=self.metrics.total_drops,
            total_rejects=self.metrics.total_rejects,
            total_timeouts=self.metrics.total_timeouts,
            avg_put_time=self.metrics.avg_put_time,
            avg_get_time=self.metrics.avg_get_time,
            utilization=self.metrics.utilization,
            last_alert_time=self.metrics.last_alert_time
        )
    
    def reset_metrics(self):
        """Reset queue metrics."""
        self.metrics = QueueMetrics(max_size=self.config.max_size)
        self.logger.info(f"Reset metrics for queue {self.name}")
    
    async def stop(self):
        """Stop the queue and cleanup tasks."""
        if self._metrics_task:
            self._metrics_task.cancel()
        self.logger.info(f"Stopped queue {self.name}")


class QueueManager:
    """Manages multiple bounded queues with centralized monitoring."""
    
    def __init__(self):
        self.queues: Dict[str, BoundedQueue] = {}
        self.logger = logging.getLogger("QueueManager")
    
    def create_queue(self, name: str, config: QueueConfig = None) -> BoundedQueue:
        """Create a new bounded queue."""
        if name in self.queues:
            raise ValueError(f"Queue {name} already exists")
        
        queue = BoundedQueue(config, name)
        self.queues[name] = queue
        self.logger.info(f"Created queue {name} with max_size={queue.config.max_size}")
        return queue
    
    def get_queue(self, name: str) -> Optional[BoundedQueue]:
        """Get an existing queue by name."""
        return self.queues.get(name)
    
    def get_all_metrics(self) -> Dict[str, QueueMetrics]:
        """Get metrics for all queues."""
        return {name: queue.get_metrics() for name, queue in self.queues.items()}
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health based on queue metrics."""
        total_queues = len(self.queues)
        if total_queues == 0:
            return {"status": "no_queues", "message": "No queues configured"}
        
        unhealthy_queues = []
        high_utilization_queues = []
        
        for name, queue in self.queues.items():
            metrics = queue.get_metrics()
            
            if metrics.utilization > 0.9:
                unhealthy_queues.append(name)
            elif metrics.utilization > 0.8:
                high_utilization_queues.append(name)
        
        if unhealthy_queues:
            return {
                "status": "critical",
                "message": f"Queues at critical utilization: {unhealthy_queues}",
                "unhealthy_queues": unhealthy_queues,
                "high_utilization_queues": high_utilization_queues
            }
        elif high_utilization_queues:
            return {
                "status": "warning",
                "message": f"Queues at high utilization: {high_utilization_queues}",
                "high_utilization_queues": high_utilization_queues
            }
        else:
            return {
                "status": "healthy",
                "message": "All queues operating normally",
                "total_queues": total_queues
            }
    
    async def stop_all(self):
        """Stop all queues."""
        for queue in self.queues.values():
            await queue.stop()
        self.queues.clear()
        self.logger.info("Stopped all queues")
