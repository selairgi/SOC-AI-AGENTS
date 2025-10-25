#!/usr/bin/env python3
"""
Integrated Medical AI Agents with SOC Security Monitoring
Combines the original medical diagnostics system with SOC security monitoring
"""

import asyncio
import argparse
import sys
import logging
import threading
import time
from typing import Optional

# Import original medical agents
from Utils.Agents import Cardiologist, Psychologist, Pulmonologist, MultidisciplinaryTeam

# Import SOC system
from config import REAL_MODE, DEFAULT_RUN_DURATION
from logging_config import setup_logging
from message_bus import MessageBus
from soc_builder import SOCBuilder
from environment_config import EnvironmentConfig
from soc_analyst import SOCAnalyst
from remediator import Remediator
from models import LogEntry

# Initialize logging
logger = setup_logging()

class MedicalSOCSystem:
    """Integrated system that combines medical AI agents with SOC security monitoring."""
    
    def __init__(self, environment_preset: str = "medical"):
        self.environment_preset = environment_preset
        
        # Initialize SOC components
        self.config = EnvironmentConfig()
        self.config.apply_preset(environment_preset)
        
        self.remediator_queue = asyncio.Queue()
        self.bus = MessageBus()
        
        # Create SOC Builder with medical-specific scan paths
        scan_paths = self.config.get_scan_paths()
        self.soc_builder = SOCBuilder(self.bus, scan_paths)
        self.soc_analyst = SOCAnalyst(self.bus, self.remediator_queue)
        self.remediator = Remediator()
        
        # Medical agents
        self.medical_agents = {}
        self.medical_reports = {}
        
        # SOC monitoring
        self.soc_running = False
        self.medical_running = False
        
    def load_medical_report(self, report_path: str) -> str:
        """Load a medical report from file."""
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error loading medical report: {e}")
            return ""
    
    def create_medical_agents(self, medical_report: str):
        """Create the medical AI agents."""
        logger.info("Creating medical AI agents...")
        
        self.medical_agents = {
            'cardiologist': Cardiologist(medical_report),
            'psychologist': Psychologist(medical_report),
            'pulmonologist': Pulmonologist(medical_report)
        }
        
        logger.info(f"Created {len(self.medical_agents)} medical agents")
    
    def run_medical_agents(self, medical_report: str):
        """Run the medical agents and collect their reports."""
        logger.info("Running medical AI agents...")
        
        # Create agents
        self.create_medical_agents(medical_report)
        
        # Run agents in parallel
        results = {}
        threads = []
        
        def run_agent(agent_name, agent):
            try:
                logger.info(f"Running {agent_name} agent...")
                result = agent.run()
                results[agent_name] = result
                logger.info(f"{agent_name} completed successfully")
                
                # Log the medical agent activity for SOC monitoring
                self.log_medical_activity(agent_name, result)
                
            except Exception as e:
                logger.error(f"Error running {agent_name}: {e}")
                results[agent_name] = f"Error: {e}"
        
        # Start all agents in separate threads
        for agent_name, agent in self.medical_agents.items():
            thread = threading.Thread(target=run_agent, args=(agent_name, agent))
            threads.append(thread)
            thread.start()
        
        # Wait for all agents to complete
        for thread in threads:
            thread.join()
        
        # Create multidisciplinary team report
        if all(key in results for key in ['cardiologist', 'psychologist', 'pulmonologist']):
            logger.info("Creating multidisciplinary team assessment...")
            multidisciplinary_team = MultidisciplinaryTeam(
                results['cardiologist'],
                results['psychologist'], 
                results['pulmonologist']
            )
            
            final_assessment = multidisciplinary_team.run()
            results['multidisciplinary'] = final_assessment
            
            # Log final assessment
            self.log_medical_activity('multidisciplinary_team', final_assessment)
        
        return results
    
    def log_medical_activity(self, agent_name: str, result: str):
        """Log medical agent activity for SOC monitoring."""
        try:
            # Create a log entry for SOC monitoring
            log = LogEntry(
                timestamp=time.time(),
                source=f"medical_agent_{agent_name}",
                message=f"Medical agent {agent_name} completed analysis",
                agent_id=f"medical_{agent_name}_agent",
                user_id="medical_system",
                session_id=f"medical_session_{int(time.time())}",
                src_ip="127.0.0.1",  # Local system
                request_id=f"medical_req_{int(time.time()*1000)}",
                status_code=200,
                extra={
                    "agent_type": "medical",
                    "agent_name": agent_name,
                    "result_length": len(result) if result else 0,
                    "medical_activity": True
                }
            )
            
            # Send to SOC system for monitoring
            if self.soc_running:
                asyncio.create_task(self.bus.publish_alert_from_log(log))
                
        except Exception as e:
            logger.error(f"Error logging medical activity: {e}")
    
    async def start_soc_monitoring(self):
        """Start the SOC monitoring system."""
        logger.info("Starting SOC security monitoring...")
        self.soc_running = True
        
        # Start SOC tasks
        soc_tasks = [
            asyncio.create_task(self.soc_builder.run(), name="soc_builder"),
            asyncio.create_task(self.soc_analyst.run(), name="soc_analyst"),
            asyncio.create_task(self.remediator.run(self.remediator_queue), name="remediator"),
        ]
        
        return soc_tasks
    
    def run_medical_diagnostics(self, report_path: str):
        """Run the medical diagnostics system."""
        logger.info("Starting medical diagnostics system...")
        self.medical_running = True
        
        # Load medical report
        medical_report = self.load_medical_report(report_path)
        if not medical_report:
            logger.error("No medical report loaded")
            return None
        
        logger.info(f"Loaded medical report ({len(medical_report)} characters)")
        
        # Run medical agents
        results = self.run_medical_agents(medical_report)
        
        # Save results
        self.save_results(results)
        
        return results
    
    def save_results(self, results: dict):
        """Save the medical analysis results."""
        try:
            with open("Results/integrated_diagnosis.txt", "w", encoding="utf-8") as f:
                f.write("=== INTEGRATED MEDICAL DIAGNOSIS WITH SOC MONITORING ===\n\n")
                
                for agent_name, result in results.items():
                    f.write(f"=== {agent_name.upper()} REPORT ===\n")
                    f.write(f"{result}\n\n")
                
                f.write("=== SOC SECURITY MONITORING STATUS ===\n")
                f.write(f"SOC System: {'ACTIVE' if self.soc_running else 'INACTIVE'}\n")
                f.write(f"Environment: {self.environment_preset}\n")
                f.write(f"Security Level: {self.config.get_environment_config().get('name', 'unknown')}\n")
                
            logger.info("Results saved to Results/integrated_diagnosis.txt")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    async def run_integrated_system(self, report_path: str, duration: Optional[float] = None):
        """Run the integrated medical + SOC system."""
        logger.info("Starting Integrated Medical AI + SOC Security System")
        logger.info("=" * 60)
        
        # Start SOC monitoring
        soc_tasks = await self.start_soc_monitoring()
        
        # Run medical diagnostics in a separate thread
        def run_medical():
            return self.run_medical_diagnostics(report_path)
        
        medical_thread = threading.Thread(target=run_medical)
        medical_thread.start()
        
        # Wait for medical diagnostics to complete
        medical_thread.join()
        
        # Continue SOC monitoring for the specified duration
        if duration:
            logger.info(f"Continuing SOC monitoring for {duration} seconds...")
            await asyncio.sleep(duration)
        else:
            # Run indefinitely until interrupted
            try:
                await asyncio.gather(*soc_tasks)
            except asyncio.CancelledError:
                logger.info("SOC monitoring cancelled")
        
        # Stop SOC system
        self.soc_running = False
        self.soc_builder.stop()
        self.soc_analyst.stop()
        self.remediator.stop()
        
        for task in soc_tasks:
            if not task.done():
                task.cancel()
        
        logger.info("Integrated system shutdown complete")

async def main():
    """Main function for the integrated system."""
    parser = argparse.ArgumentParser(description="Integrated Medical AI + SOC Security System")
    parser.add_argument("--report", type=str, default="Medical Reports/Medical Rerort - Michael Johnson - Panic Attack Disorder.txt",
                        help="Path to medical report file")
    parser.add_argument("--duration", type=float, default=30,
                        help="Duration to run SOC monitoring after medical analysis (seconds)")
    parser.add_argument("--environment", type=str, default="medical", 
                        choices=["medical", "financial", "development", "production"],
                        help="SOC environment preset")
    parser.add_argument("--log-level", type=str, default="INFO", 
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level")
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Create and run integrated system
    system = MedicalSOCSystem(args.environment)
    
    try:
        await system.run_integrated_system(args.report, args.duration)
    except KeyboardInterrupt:
        logger.info("System stopped by user")
    except Exception as e:
        logger.error(f"System error: {e}")

if __name__ == "__main__":
    asyncio.run(main())

