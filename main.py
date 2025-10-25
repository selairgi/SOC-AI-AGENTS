"""
Main execution logic and CLI for SOC AI Agents.
"""

import asyncio
import argparse
import sys
import unittest
import logging
from typing import Optional

from config import REAL_MODE, DEFAULT_RUN_DURATION
from logging_config import setup_logging
from message_bus import MessageBus
from soc_builder import SOCBuilder
from environment_config import EnvironmentConfig
from soc_analyst import SOCAnalyst
from remediator import Remediator


# Initialize default logging
logger = setup_logging()


async def main(run_duration: Optional[float] = None, environment_preset: str = "development"):
    """Create agents, run them and optionally stop after `run_duration` seconds.

    If `run_duration` is provided the function will cancel all tasks after the timeout and return.
    This allows safe automated testing and prevents infinite runs when invoked from CI or demos.
    """
    # Load environment configuration
    config = EnvironmentConfig()
    config.apply_preset(environment_preset)
    
    remediator_queue = asyncio.Queue()
    bus = MessageBus()
    
    # Create SOC Builder with environment-specific scan paths
    scan_paths = config.get_scan_paths()
    builder = SOCBuilder(bus, scan_paths)
    
    analyst = SOCAnalyst(bus, remediator_queue)
    rem = Remediator()

    # create long-running tasks
    tasks = [
        asyncio.create_task(builder.run(), name="soc_builder"),
        asyncio.create_task(analyst.run(), name="soc_analyst"),
        asyncio.create_task(rem.run(remediator_queue), name="remediator"),
    ]

    async def stop_after(delay: float):
        await asyncio.sleep(delay)
        logger.info(f"run_duration {delay}s elapsed — stopping agents")
        builder.stop()
        analyst.stop()
        rem.stop()
        for t in tasks:
            t.cancel()

    stopper = None
    if run_duration is not None and run_duration > 0:
        stopper = asyncio.create_task(stop_after(run_duration), name="stopper")

    try:
        # Wait for tasks to complete or be cancelled. If run_duration is None it will run forever.
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("tasks cancelled — shutting down")
    finally:
        # ensure stopper is cancelled if still pending
        if stopper and not stopper.done():
            stopper.cancel()


# Utility that safely runs `main()` whether or not an event loop is already active
def run_main_blocking(duration: Optional[float] = DEFAULT_RUN_DURATION, environment_preset: str = "development"):
    loop = asyncio.get_event_loop()
    if loop.is_running():
        # Running inside an existing event loop (e.g., Jupyter). Schedule the main task and return.
        logger.info("detected running event loop — scheduling main() as a task")
        asyncio.create_task(main(duration, environment_preset))
        logger.info(f"main() scheduled for {duration}s with {environment_preset} environment. If you're in an interactive shell, wait {duration}s to observe output.")
    else:
        # Safe to use asyncio.run in a standalone script
        asyncio.run(main(duration, environment_preset))


# -------------------- Basic smoke-test helper --------------------
async def _smoke_test_once():
    """A very small smoke test that runs the system for 2 seconds and ensures it executes without
    raising exceptions. Returns True on success. This test function is intended for quick local
    verification, not as a full unit-test suite.
    """
    try:
        await main(run_duration=2)
        return True
    except Exception as e:
        logger.error(f"smoke_test failed: {e}")
        return False


def smoke_test():
    loop = asyncio.get_event_loop()
    if loop.is_running():
        logger.info("event loop running — scheduling smoke test task")
        asyncio.create_task(_smoke_test_once())
    else:
        return asyncio.run(_smoke_test_once())


# -------------------- CLI --------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SOC AI Agents prototype runner")
    parser.add_argument("--duration", type=float, default=DEFAULT_RUN_DURATION,
                        help=f"How many seconds to run the demo (default {DEFAULT_RUN_DURATION}). Use 0 for indefinite run")
    parser.add_argument("--real", action="store_true", help="Enable REAL_MODE (will attempt real remediation) - use with caution")
    parser.add_argument("--smoke-test", action="store_true", help="Run a short smoke test and exit")
    parser.add_argument("--run-tests", action="store_true", help="Run unit tests and exit")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Set logging level (default: INFO)")
    parser.add_argument("--log-format", type=str, default=None,
                        help="Custom log format string (default: timestamped structured format)")
    parser.add_argument("--environment", type=str, default="development", 
                        choices=["medical", "financial", "development", "production", "custom"],
                        help="Environment preset to use (default: development)")
    args = parser.parse_args()

    # Setup logging with CLI arguments
    logger = setup_logging(args.log_level, args.log_format)
    
    if args.real:
        logger.warning("enabling REAL_MODE - be careful!")
        # Note: In a real implementation, you'd need to modify the config module
        # For now, we'll just log the warning
        import config
        config.REAL_MODE = True

    # Handle run-tests first: run tests and exit (prevents starting the main agents)
    if args.run_tests:
        logger.info('running unit tests')
        # Ensure unittest doesn't try to interpret CLI args
        unittest.main(argv=[sys.argv[0]], exit=False)
        sys.exit(0)

    if args.smoke_test:
        logger.info("running smoke test (2s)")
        ok = smoke_test()
        logger.info(f"smoke test result: {ok}")
    else:
        try:
            # Use helper that handles running-loop vs no-loop situations
            run_main_blocking(args.duration if args.duration > 0 else None, args.environment)
            # If running in a normal script, run_main_blocking will block until completion.
            # If running in an interactive environment (loop running), we've scheduled the task and
            # should NOT call asyncio.run(). The user can observe the scheduled run in the current
            # session.
        except KeyboardInterrupt:
            logger.info("Stopped by user")
