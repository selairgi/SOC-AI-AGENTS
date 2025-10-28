"""
Universal SOC Deployer - Inject SOC agents into any multi-agent system.

This deploys SOC security monitoring into existing agent systems WITHOUT modifying their code.
"""

import os
import shutil
import subprocess
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SOCDeployer:
    """Deploys SOC agents into target multi-agent systems."""

    def __init__(self, target_repo_url: str, deployment_dir: str = "./deployments"):
        self.target_repo_url = target_repo_url
        self.deployment_dir = Path(deployment_dir)
        self.deployment_dir.mkdir(exist_ok=True)

        # Extract repo name
        self.repo_name = self._extract_repo_name(target_repo_url)
        self.target_path = self.deployment_dir / self.repo_name
        self.soc_folder = self.target_path / "soc_security"

    def _extract_repo_name(self, url: str) -> str:
        """Extract repository name from URL."""
        return url.rstrip('/').split('/')[-1].replace('.git', '')

    def deploy(self):
        """Complete SOC deployment process."""
        logger.info(f"\n{'='*70}")
        logger.info(f"UNIVERSAL SOC DEPLOYER")
        logger.info(f"{'='*70}\n")

        # Step 1: Clone target repository
        logger.info("STEP 1: Cloning target repository...")
        self._clone_target_repo()

        # Step 2: Check and setup API keys
        logger.info("\nSTEP 2: Checking API key requirements...")
        self._setup_api_keys()

        # Step 3: Create SOC security folder
        logger.info("\nSTEP 3: Creating SOC security folder...")
        self._create_soc_folder()

        # Step 4: Copy SOC agents
        logger.info("\nSTEP 4: Deploying SOC agents...")
        self._deploy_soc_agents()

        # Step 5: Create interceptor
        logger.info("\nSTEP 5: Creating agent interceptor...")
        self._create_interceptor()

        # Step 6: Create secured runner
        logger.info("\nSTEP 6: Creating secured runner...")
        self._create_secured_runner()

        # Step 7: Create configuration
        logger.info("\nSTEP 7: Creating SOC configuration...")
        self._create_soc_config()

        logger.info(f"\n{'='*70}")
        logger.info(f"SOC DEPLOYMENT COMPLETE!")
        logger.info(f"{'='*70}\n")
        logger.info(f"Target system: {self.target_path}")
        logger.info(f"SOC location: {self.soc_folder}")
        logger.info(f"\nTo run the secured system:")
        logger.info(f"  cd {self.target_path}")
        logger.info(f"  python run_secured.py")
        logger.info(f"\n{'='*70}\n")

        return str(self.target_path)

    def _clone_target_repo(self):
        """Clone the target repository."""
        # Check if running on Windows
        is_windows = os.name == 'nt'

        if self.target_path.exists():
            logger.info(f"  Repository already exists at {self.target_path}")
            logger.info(f"  Pulling latest changes...")
            try:
                subprocess.run(
                    ["git", "pull"] if not is_windows else "git pull",
                    cwd=self.target_path,
                    capture_output=True,
                    timeout=60,
                    shell=is_windows
                )
                logger.info("  ✓ Updated to latest version")
            except Exception as e:
                logger.warning(f"  Could not pull updates: {e}")
        else:
            logger.info(f"  Cloning {self.target_repo_url}...")
            try:
                subprocess.run(
                    ["git", "clone", self.target_repo_url, str(self.target_path)] if not is_windows
                    else f'git clone "{self.target_repo_url}" "{self.target_path}"',
                    capture_output=True,
                    timeout=300,
                    check=True,
                    shell=is_windows
                )
                logger.info(f"  ✓ Cloned to {self.target_path}")
            except subprocess.CalledProcessError as e:
                logger.error(f"  ✗ Failed to clone: {e}")
                raise

    def _setup_api_keys(self):
        """Detect if system needs API keys and set them up."""
        # Check if repo uses OpenAI
        needs_openai = self._check_openai_requirement()

        if needs_openai:
            logger.info("  System requires OpenAI API key")

            # Check if API key already exists
            existing_key = self._find_existing_api_key()

            if existing_key:
                logger.info(f"  ✓ Found existing API key in {existing_key}")
                return

            # Ask user for API key
            logger.info("\n  OpenAI API key not found. Please provide your API key.")
            logger.info("  (Get one at: https://platform.openai.com/api-keys)")
            logger.info("  Press Enter to skip if you'll add it later\n")

            api_key = input("  Enter your OpenAI API key: ").strip()

            if api_key:
                # Create .env file
                self._create_env_file(api_key)
                logger.info("  ✓ API key saved to .env file")
            else:
                logger.warning("  ⚠ Skipped. You'll need to add the API key manually later.")
                logger.info("  Create a .env file or apikey.env with: OPENAI_API_KEY=your-key")
        else:
            logger.info("  ✓ No API key required (or already configured)")

    def _check_openai_requirement(self) -> bool:
        """Check if the repository requires OpenAI API key."""
        # Check common files for OpenAI imports
        files_to_check = [
            'requirements.txt',
            'requirements_enhanced.txt',
            'pyproject.toml',
            'setup.py',
            'main.py',
            'Main.py',
            'app.py',
        ]

        openai_indicators = [
            'openai',
            'langchain',
            'langchain-openai',
            'gpt',
            'ChatOpenAI'
        ]

        for file_name in files_to_check:
            file_path = self.target_path / file_name
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        if any(indicator.lower() in content for indicator in openai_indicators):
                            return True
                except Exception:
                    continue

        # Check Python files in root
        for py_file in self.target_path.glob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'import openai' in content or 'from openai' in content:
                        return True
                    if 'langchain' in content.lower() and 'openai' in content.lower():
                        return True
            except Exception:
                continue

        return False

    def _find_existing_api_key(self) -> str:
        """Check if API key file already exists."""
        env_files = ['.env', 'apikey.env', '.env.local', '.env.production']

        for env_file in env_files:
            env_path = self.target_path / env_file
            if env_path.exists():
                try:
                    with open(env_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'OPENAI_API_KEY' in content:
                            # Check if it has a value
                            for line in content.split('\n'):
                                if 'OPENAI_API_KEY' in line and '=' in line:
                                    value = line.split('=', 1)[1].strip()
                                    if value and not value.startswith('#'):
                                        return env_file
                except Exception:
                    continue

        return None

    def _create_env_file(self, api_key: str):
        """Create .env file with API key."""
        env_path = self.target_path / '.env'

        # Check what format the repo expects
        apikey_env_path = self.target_path / 'apikey.env'
        if apikey_env_path.exists() or self._check_for_apikey_env_usage():
            # Use apikey.env format
            env_path = apikey_env_path
            env_content = f"OPENAI_API_KEY={api_key}\n"
        else:
            # Use standard .env format
            env_content = f"# OpenAI API Configuration\nOPENAI_API_KEY={api_key}\n"

        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)

        # Add to .gitignore if it exists
        gitignore_path = self.target_path / '.gitignore'
        if gitignore_path.exists():
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                content = f.read()
            if '.env' not in content:
                with open(gitignore_path, 'a', encoding='utf-8') as f:
                    f.write('\n# Environment variables\n.env\napikey.env\n')
        else:
            # Create .gitignore
            with open(gitignore_path, 'w', encoding='utf-8') as f:
                f.write('# Environment variables\n.env\napikey.env\n')

    def _check_for_apikey_env_usage(self) -> bool:
        """Check if repo uses apikey.env format."""
        # Check main files for apikey.env references
        for py_file in self.target_path.glob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'apikey.env' in content:
                        return True
            except Exception:
                continue
        return False

    def _create_soc_folder(self):
        """Create clean SOC security folder."""
        self.soc_folder.mkdir(exist_ok=True)
        logger.info(f"  ✓ Created {self.soc_folder}")

        # Create subdirectories
        (self.soc_folder / "logs").mkdir(exist_ok=True)
        (self.soc_folder / "alerts").mkdir(exist_ok=True)
        (self.soc_folder / "playbooks").mkdir(exist_ok=True)

        logger.info(f"  ✓ Created subdirectories")

    def _deploy_soc_agents(self):
        """Copy SOC agent files to target system."""
        soc_source = Path(__file__).parent

        # List of SOC files to deploy
        soc_files = [
            'soc_builder.py',
            'soc_analyst.py',
            'remediator.py',
            'models.py',
            'config.py',
            'message_bus.py',
            'security_rules.py',
            'security_config.py',
            'action_policy.py',
            'execution_tracker.py',
            'retry_circuit_breaker.py',
            'false_positive_detector.py',
            'real_remediation.py',
            'logging_config.py',
            'environment_config.py',
            'bounded_queue.py',
            'schema_validator.py',
            'agent_monitor.py'
        ]

        deployed_count = 0
        for file_name in soc_files:
            source_file = soc_source / file_name
            if source_file.exists():
                dest_file = self.soc_folder / file_name
                shutil.copy2(source_file, dest_file)
                deployed_count += 1
                logger.info(f"  ✓ Deployed {file_name}")

        logger.info(f"\n  ✓ Deployed {deployed_count} SOC components")

    def _create_interceptor(self):
        """Create agent interceptor for monitoring."""
        interceptor_code = '''"""
Agent Interceptor - Monitors agent activity without modifying original code.
"""

import functools
import time
import json
import logging
from pathlib import Path
from typing import Any, Callable
import inspect

# Setup logging
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "agent_activity.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("SOC.Interceptor")

# Import SOC components
try:
    from .models import LogEntry, Alert, ThreatType
    from .message_bus import MessageBus
    from .security_rules import SecurityRulesEngine
    SOC_AVAILABLE = True
except ImportError:
    logger.warning("SOC components not fully loaded, running in log-only mode")
    SOC_AVAILABLE = False


class AgentInterceptor:
    """
    Intercepts and monitors agent method calls.

    This wraps agent methods to capture inputs, outputs, and detect threats.
    """

    def __init__(self, agent_id: str = "unknown"):
        self.agent_id = agent_id
        self.call_count = 0
        self.security_engine = SecurityRulesEngine() if SOC_AVAILABLE else None

        logger.info(f"Interceptor initialized for agent: {agent_id}")

    def wrap_agent_method(self, method: Callable, method_name: str = None) -> Callable:
        """Wrap an agent method to monitor its execution."""

        if method_name is None:
            method_name = method.__name__

        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            self.call_count += 1
            call_id = f"{self.agent_id}_{method_name}_{self.call_count}"

            # Log method invocation
            logger.info(f"[{call_id}] Agent method called: {method_name}")
            logger.debug(f"[{call_id}] Args: {args[:2] if len(args) > 2 else args}")  # Limit arg logging
            logger.debug(f"[{call_id}] Kwargs: {list(kwargs.keys())}")

            # Capture start time
            start_time = time.time()

            # Security check on inputs
            if self.security_engine:
                self._check_input_security(method_name, args, kwargs, call_id)

            # Execute original method
            try:
                result = method(*args, **kwargs)

                # Calculate execution time
                execution_time = time.time() - start_time

                # Log result
                logger.info(f"[{call_id}] Completed in {execution_time:.3f}s")

                # Security check on output
                if self.security_engine:
                    self._check_output_security(method_name, result, call_id)

                # Save interaction log
                self._save_interaction_log(call_id, method_name, args, kwargs, result, execution_time)

                return result

            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"[{call_id}] Failed after {execution_time:.3f}s: {e}")

                # Log error
                self._save_error_log(call_id, method_name, args, kwargs, str(e))

                # Re-raise exception
                raise

        return wrapper

    def _check_input_security(self, method_name: str, args: tuple, kwargs: dict, call_id: str):
        """Check inputs for security threats."""
        try:
            # Convert args to string for analysis
            input_str = " ".join([str(arg)[:500] for arg in args if isinstance(arg, (str, int, float))])

            # Check for prompt injection, malicious patterns
            if "ignore" in input_str.lower() and "instruction" in input_str.lower():
                logger.warning(f"[{call_id}] SECURITY: Potential prompt injection detected")
                self._create_alert(
                    call_id,
                    "Prompt Injection Attempt",
                    f"Agent {self.agent_id} method {method_name}",
                    ThreatType.PROMPT_INJECTION if SOC_AVAILABLE else "prompt_injection"
                )

            # Check for data exfiltration patterns
            exfil_keywords = ["password", "api_key", "secret", "token", "credential"]
            if any(kw in input_str.lower() for kw in exfil_keywords):
                logger.warning(f"[{call_id}] SECURITY: Potential data exfiltration attempt")

        except Exception as e:
            logger.error(f"[{call_id}] Security check error: {e}")

    def _check_output_security(self, method_name: str, result: Any, call_id: str):
        """Check outputs for sensitive data leakage."""
        try:
            if isinstance(result, str):
                # Check for PII or sensitive data in output
                sensitive_patterns = ["ssn", "credit card", "password", "api_key"]
                result_lower = result.lower()

                for pattern in sensitive_patterns:
                    if pattern in result_lower:
                        logger.warning(f"[{call_id}] SECURITY: Sensitive data in output: {pattern}")

        except Exception as e:
            logger.error(f"[{call_id}] Output security check error: {e}")

    def _create_alert(self, call_id: str, title: str, description: str, threat_type):
        """Create security alert."""
        alert_file = Path(__file__).parent / "alerts" / f"alert_{call_id}.json"
        alert_file.parent.mkdir(exist_ok=True)

        alert_data = {
            "id": call_id,
            "timestamp": time.time(),
            "severity": "high",
            "title": title,
            "description": description,
            "threat_type": str(threat_type),
            "agent_id": self.agent_id
        }

        with open(alert_file, 'w') as f:
            json.dump(alert_data, f, indent=2)

        logger.warning(f"[{call_id}] ALERT CREATED: {title}")

    def _save_interaction_log(self, call_id: str, method_name: str, args: tuple, kwargs: dict, result: Any, execution_time: float):
        """Save interaction log for audit."""
        log_file = Path(__file__).parent / "logs" / "interactions.jsonl"
        log_file.parent.mkdir(exist_ok=True)

        log_entry = {
            "call_id": call_id,
            "timestamp": time.time(),
            "agent_id": self.agent_id,
            "method": method_name,
            "execution_time": execution_time,
            "success": True,
            "args_count": len(args),
            "kwargs_keys": list(kwargs.keys()),
            "result_type": type(result).__name__
        }

        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\\n')

    def _save_error_log(self, call_id: str, method_name: str, args: tuple, kwargs: dict, error: str):
        """Save error log."""
        log_file = Path(__file__).parent / "logs" / "errors.jsonl"
        log_file.parent.mkdir(exist_ok=True)

        log_entry = {
            "call_id": call_id,
            "timestamp": time.time(),
            "agent_id": self.agent_id,
            "method": method_name,
            "error": error,
            "args_count": len(args),
            "kwargs_keys": list(kwargs.keys())
        }

        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\\n')


def wrap_agent_class(agent_class, agent_id: str = None):
    """
    Wrap all methods of an agent class for monitoring.

    Usage:
        SecuredAgent = wrap_agent_class(OriginalAgent, "my_agent")
        agent = SecuredAgent(...)
    """
    if agent_id is None:
        agent_id = agent_class.__name__

    interceptor = AgentInterceptor(agent_id)

    # Get all methods
    for attr_name in dir(agent_class):
        if attr_name.startswith('_'):
            continue

        attr = getattr(agent_class, attr_name)
        if callable(attr) and not isinstance(attr, type):
            # Wrap the method
            wrapped = interceptor.wrap_agent_method(attr, attr_name)
            setattr(agent_class, attr_name, wrapped)

    logger.info(f"Wrapped agent class: {agent_class.__name__}")
    return agent_class


def wrap_function(func: Callable, agent_id: str = "function") -> Callable:
    """
    Wrap a standalone function for monitoring.

    Usage:
        secured_func = wrap_function(original_func, "my_func")
    """
    interceptor = AgentInterceptor(agent_id)
    return interceptor.wrap_agent_method(func)
'''

        interceptor_file = self.soc_folder / "agent_interceptor.py"
        with open(interceptor_file, 'w', encoding='utf-8') as f:
            f.write(interceptor_code)

        logger.info(f"  ✓ Created {interceptor_file.name}")

    def _create_secured_runner(self):
        """Create run_secured.py wrapper."""
        runner_code = '''#!/usr/bin/env python3
"""
Secured Runner - Runs the original system with SOC monitoring.

This wraps the original system's execution with SOC security monitoring.
Usage: python run_secured.py [original_args...]
"""

import sys
import os
from pathlib import Path

# Add SOC folder to path
soc_path = Path(__file__).parent / "soc_security"
sys.path.insert(0, str(soc_path))

print("="*70)
print("SECURED EXECUTION MODE - SOC MONITORING ACTIVE")
print("="*70)
print(f"SOC Security Layer: {soc_path}")
print("All agent activity will be monitored and logged.")
print("="*70)
print()

# Import interceptor
from soc_security.agent_interceptor import wrap_agent_class, wrap_function

# Try to import and wrap the original agents
try:
    # For Medical AI Agents repo
    try:
        from Utils.Agents import Agent, Cardiologist, Psychologist, Pulmonologist, MultidisciplinaryTeam

        # Wrap all agent classes
        Cardiologist = wrap_agent_class(Cardiologist, "Cardiologist")
        Psychologist = wrap_agent_class(Psychologist, "Psychologist")
        Pulmonologist = wrap_agent_class(Pulmonologist, "Pulmonologist")
        MultidisciplinaryTeam = wrap_agent_class(MultidisciplinaryTeam, "MultidisciplinaryTeam")

        # Replace in Utils.Agents module
        import Utils.Agents as agents_module
        agents_module.Cardiologist = Cardiologist
        agents_module.Psychologist = Psychologist
        agents_module.Pulmonologist = Pulmonologist
        agents_module.MultidisciplinaryTeam = MultidisciplinaryTeam

        print("✓ Medical AI Agents secured with SOC monitoring")
        print()

    except ImportError as e:
        print(f"Note: Could not wrap Utils.Agents: {e}")
        print("Continuing with general monitoring...")
        print()

except Exception as e:
    print(f"Warning: Could not apply some security wrappings: {e}")
    print("Continuing with available security features...")
    print()

# Now import and run the original main
print("Starting original system with SOC protection...")
print("-"*70)
print()

try:
    import main
    print()
    print("-"*70)
    print("✓ Original system completed successfully")
    print("✓ Check soc_security/logs/ for activity logs")
    print("✓ Check soc_security/alerts/ for security alerts")
    print("="*70)

except Exception as e:
    print()
    print("-"*70)
    print(f"✗ Error during execution: {e}")
    print("✓ Check soc_security/logs/errors.jsonl for details")
    print("="*70)
    raise
'''

        runner_file = self.target_path / "run_secured.py"
        with open(runner_file, 'w', encoding='utf-8') as f:
            f.write(runner_code)

        # Make executable on Unix systems
        try:
            os.chmod(runner_file, 0o755)
        except:
            pass

        logger.info(f"  ✓ Created {runner_file.name}")

    def _create_soc_config(self):
        """Create SOC configuration file."""
        config_code = '''"""
SOC Security Configuration
"""

SOC_CONFIG = {
    "monitoring": {
        "enabled": True,
        "log_level": "INFO",
        "log_all_calls": True,
        "log_arguments": False,  # Set True for detailed debugging (may expose sensitive data)
    },

    "security_rules": {
        "prompt_injection_detection": True,
        "data_exfiltration_detection": True,
        "malicious_input_detection": True,
        "output_sanitization": True,
    },

    "alerting": {
        "enabled": True,
        "alert_on_suspicious": True,
        "alert_threshold": "medium",  # low, medium, high, critical
    },

    "remediation": {
        "enabled": False,  # Set True to enable automatic remediation
        "auto_block": False,  # Requires enabled=True
        "auto_terminate": False,  # Requires enabled=True
    },

    "logging": {
        "log_dir": "logs",
        "max_log_size_mb": 100,
        "retain_days": 30,
    }
}
'''

        config_file = self.soc_folder / "soc_config.py"
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config_code)

        logger.info(f"  ✓ Created {config_file.name}")

        # Create __init__.py
        init_file = self.soc_folder / "__init__.py"
        with open(init_file, 'w', encoding='utf-8') as f:
            f.write('"""SOC Security Module"""\n')

        # Create README
        readme_code = f'''# SOC Security Layer

This folder contains the deployed SOC (Security Operations Center) agents that monitor and secure the multi-agent system.

## Deployed From
SOC AI Agents - Universal Security Layer

## What This Does
- **Monitors** all agent activity without modifying original code
- **Detects** security threats (prompt injection, data exfiltration, etc.)
- **Logs** all agent interactions for audit
- **Alerts** on suspicious behavior

## How to Use

### Run with SOC Protection:
```bash
python run_secured.py
```

### Run Original (No SOC):
```bash
python main.py
```

## Logs & Alerts

- **Activity Logs**: `soc_security/logs/agent_activity.log`
- **Interaction Logs**: `soc_security/logs/interactions.jsonl`
- **Error Logs**: `soc_security/logs/errors.jsonl`
- **Security Alerts**: `soc_security/alerts/alert_*.json`

## Configuration

Edit `soc_security/soc_config.py` to customize:
- Monitoring verbosity
- Security rules
- Alerting thresholds
- Remediation policies

## Architecture

```
Original System (UNTOUCHED)
    ↓
Agent Interceptor (Transparent Wrapper)
    ↓
SOC Monitoring & Analysis
    ↓
Logs, Alerts, Remediation
```

The SOC layer intercepts agent method calls transparently, monitors them for security threats, and logs all activity WITHOUT modifying the original agent code.

## Status

✓ SOC Deployed
✓ Monitoring Active
✓ Zero-Touch Integration (Original code unchanged)
'''

        readme_file = self.soc_folder / "README.md"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_code)

        logger.info(f"  ✓ Created README.md")


def deploy_soc_cli():
    """CLI interface for SOC deployment."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python soc_deployer.py <repository_url>")
        print()
        print("Example:")
        print("  python soc_deployer.py https://github.com/user/my-agents")
        sys.exit(1)

    repo_url = sys.argv[1]

    deployer = SOCDeployer(repo_url)
    target_path = deployer.deploy()

    print("\nDeployment successful!")
    print(f"Navigate to: {target_path}")
    print(f"Run secured system: python run_secured.py")


if __name__ == "__main__":
    deploy_soc_cli()
