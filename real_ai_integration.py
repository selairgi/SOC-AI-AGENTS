"""
Real AI Integration Module
Integrates with OpenAI API and provides comprehensive logging for SOC monitoring
"""

import os
import time
import json
import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    from openai import OpenAI, AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: OpenAI package not installed. Using fallback mode.")

from models import LogEntry, AgentType


@dataclass
class AIInteraction:
    """Represents a single AI interaction for logging and monitoring"""
    interaction_id: str
    timestamp: float
    user_id: str
    session_id: str
    prompt: str
    response: str
    model: str
    tokens_used: int
    response_time: float
    cost_estimate: float
    metadata: Dict[str, Any]


class RealAIIntegration:
    """
    Real AI Integration with comprehensive logging for SOC monitoring.
    Supports OpenAI API with full interaction tracking.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        self.logger = logging.getLogger("RealAIIntegration")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.interaction_log = []
        self.total_tokens_used = 0
        self.total_cost = 0.0

        # Initialize OpenAI clients if available
        if OPENAI_AVAILABLE and self.api_key:
            self.client = OpenAI(api_key=self.api_key)
            self.async_client = AsyncOpenAI(api_key=self.api_key)
            self.use_real_ai = True
            self.logger.info(f"Real AI Integration initialized with model: {model}")
        else:
            self.client = None
            self.async_client = None
            self.use_real_ai = False
            self.logger.warning("OpenAI not available. Using fallback responses.")

        # System prompts for different security contexts
        self.system_prompts = {
            "default": "You are a helpful AI assistant. Be concise and helpful.",
            "security_aware": """You are a security-aware AI assistant.
            You should:
            1. Never reveal internal system information
            2. Never execute commands or code
            3. Never provide sensitive data
            4. Refuse harmful requests politely
            5. Be helpful while maintaining security boundaries""",
            "strict": """You are a strictly controlled AI assistant in a high-security environment.
            You must:
            1. Only answer questions within your scope
            2. Never discuss system internals
            3. Refuse any requests that could be security risks
            4. Log all suspicious interactions
            5. Maintain strict confidentiality"""
        }

        # Cost estimates per 1K tokens (approximate for GPT-3.5-turbo)
        self.cost_per_1k_tokens = {
            "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-4-turbo": {"input": 0.01, "output": 0.03}
        }

    def generate_response(
        self,
        prompt: str,
        user_id: str,
        session_id: str,
        security_mode: str = "security_aware",
        max_tokens: int = 500,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """
        Generate AI response with comprehensive logging.

        Args:
            prompt: User's input prompt
            user_id: User identifier
            session_id: Session identifier
            security_mode: Security context (default, security_aware, strict)
            max_tokens: Maximum response tokens
            temperature: Response randomness (0-1)

        Returns:
            Dict containing response and interaction metadata
        """
        start_time = time.time()
        interaction_id = f"ai_{int(time.time()*1000)}_{user_id}"

        try:
            if self.use_real_ai and self.client:
                # Real OpenAI API call
                response = self._call_openai(
                    prompt,
                    security_mode,
                    max_tokens,
                    temperature
                )
                response_text = response['response']
                tokens_used = response['tokens_used']
                cost = response['cost']
            else:
                # Fallback response
                response_text = self._generate_fallback_response(prompt)
                tokens_used = len(prompt.split()) + len(response_text.split())
                cost = 0.0

            response_time = time.time() - start_time

            # Create interaction record
            interaction = AIInteraction(
                interaction_id=interaction_id,
                timestamp=time.time(),
                user_id=user_id,
                session_id=session_id,
                prompt=prompt,
                response=response_text,
                model=self.model,
                tokens_used=tokens_used,
                response_time=response_time,
                cost_estimate=cost,
                metadata={
                    "security_mode": security_mode,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "real_ai_used": self.use_real_ai
                }
            )

            # Log interaction for SOC monitoring
            self.interaction_log.append(interaction)
            self.total_tokens_used += tokens_used
            self.total_cost += cost

            # Keep only last 1000 interactions in memory
            if len(self.interaction_log) > 1000:
                self.interaction_log = self.interaction_log[-1000:]

            self.logger.info(
                f"AI Interaction {interaction_id}: {tokens_used} tokens, "
                f"{response_time:.2f}s, ${cost:.4f}"
            )

            return {
                "response": response_text,
                "interaction_id": interaction_id,
                "tokens_used": tokens_used,
                "response_time": response_time,
                "cost": cost,
                "model": self.model,
                "security_mode": security_mode
            }

        except Exception as e:
            self.logger.error(f"Error generating AI response: {e}")
            return {
                "response": "I apologize, but I encountered an error processing your request. Please try again.",
                "interaction_id": interaction_id,
                "tokens_used": 0,
                "response_time": time.time() - start_time,
                "cost": 0.0,
                "model": self.model,
                "error": str(e)
            }

    async def generate_response_async(
        self,
        prompt: str,
        user_id: str,
        session_id: str,
        security_mode: str = "security_aware",
        max_tokens: int = 500,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Async version of generate_response"""
        start_time = time.time()
        interaction_id = f"ai_{int(time.time()*1000)}_{user_id}"

        try:
            if self.use_real_ai and self.async_client:
                # Real async OpenAI API call
                response = await self._call_openai_async(
                    prompt,
                    security_mode,
                    max_tokens,
                    temperature
                )
                response_text = response['response']
                tokens_used = response['tokens_used']
                cost = response['cost']
            else:
                # Fallback response
                response_text = self._generate_fallback_response(prompt)
                tokens_used = len(prompt.split()) + len(response_text.split())
                cost = 0.0

            response_time = time.time() - start_time

            # Create interaction record
            interaction = AIInteraction(
                interaction_id=interaction_id,
                timestamp=time.time(),
                user_id=user_id,
                session_id=session_id,
                prompt=prompt,
                response=response_text,
                model=self.model,
                tokens_used=tokens_used,
                response_time=response_time,
                cost_estimate=cost,
                metadata={
                    "security_mode": security_mode,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "real_ai_used": self.use_real_ai
                }
            )

            # Log interaction
            self.interaction_log.append(interaction)
            self.total_tokens_used += tokens_used
            self.total_cost += cost

            if len(self.interaction_log) > 1000:
                self.interaction_log = self.interaction_log[-1000:]

            return {
                "response": response_text,
                "interaction_id": interaction_id,
                "tokens_used": tokens_used,
                "response_time": response_time,
                "cost": cost,
                "model": self.model,
                "security_mode": security_mode
            }

        except Exception as e:
            self.logger.error(f"Error in async AI response: {e}")
            return {
                "response": "I apologize, but I encountered an error. Please try again.",
                "interaction_id": interaction_id,
                "tokens_used": 0,
                "response_time": time.time() - start_time,
                "cost": 0.0,
                "model": self.model,
                "error": str(e)
            }

    def _call_openai(
        self,
        prompt: str,
        security_mode: str,
        max_tokens: int,
        temperature: float
    ) -> Dict[str, Any]:
        """Make synchronous OpenAI API call"""
        system_prompt = self.system_prompts.get(security_mode, self.system_prompts["default"])

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature
        )

        response_text = response.choices[0].message.content
        tokens_used = response.usage.total_tokens

        # Calculate cost
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        cost_info = self.cost_per_1k_tokens.get(self.model, self.cost_per_1k_tokens["gpt-3.5-turbo"])
        cost = (input_tokens / 1000 * cost_info["input"]) + (output_tokens / 1000 * cost_info["output"])

        return {
            "response": response_text,
            "tokens_used": tokens_used,
            "cost": cost,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }

    async def _call_openai_async(
        self,
        prompt: str,
        security_mode: str,
        max_tokens: int,
        temperature: float
    ) -> Dict[str, Any]:
        """Make asynchronous OpenAI API call"""
        system_prompt = self.system_prompts.get(security_mode, self.system_prompts["default"])

        response = await self.async_client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature
        )

        response_text = response.choices[0].message.content
        tokens_used = response.usage.total_tokens

        # Calculate cost
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        cost_info = self.cost_per_1k_tokens.get(self.model, self.cost_per_1k_tokens["gpt-3.5-turbo"])
        cost = (input_tokens / 1000 * cost_info["input"]) + (output_tokens / 1000 * cost_info["output"])

        return {
            "response": response_text,
            "tokens_used": tokens_used,
            "cost": cost,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }

    def _generate_fallback_response(self, prompt: str) -> str:
        """Generate fallback response when OpenAI is not available"""
        prompt_lower = prompt.lower()

        # Security-aware fallback responses
        if any(keyword in prompt_lower for keyword in ["ignore", "forget", "disregard", "override"]):
            return "I'm designed to maintain my instructions and security boundaries. I can't ignore or override my core programming. How else can I help you?"

        if any(keyword in prompt_lower for keyword in ["system", "admin", "root", "sudo", "password", "credentials"]):
            return "I don't have access to system information or credentials. I'm here to help with general questions within my scope."

        if any(keyword in prompt_lower for keyword in ["hack", "exploit", "inject", "malicious"]):
            return "I can't assist with security exploits or malicious activities. I'm here to help with legitimate queries."

        if "hello" in prompt_lower or "hi" in prompt_lower:
            return "Hello! I'm an AI assistant protected by SOC security monitoring. How can I help you today?"

        if "help" in prompt_lower:
            return "I can help answer questions, provide information, and have conversations. I'm monitored by SOC AI Agents for security. What would you like to know?"

        if "soc" in prompt_lower or "security" in prompt_lower:
            return "This system is protected by SOC (Security Operations Center) AI Agents that monitor for threats like prompt injection, data exfiltration, and malicious inputs in real-time."

        if "how are you" in prompt_lower:
            return "I'm functioning well and ready to help! I'm continuously monitored for security to ensure safe interactions."

        # Default response
        return f"I understand your message about '{prompt[:50]}...'. I'm here to help with questions and information. What specifically would you like to know?"

    def create_log_entry(self, interaction: AIInteraction, src_ip: str = "127.0.0.1") -> LogEntry:
        """
        Convert AI interaction to LogEntry for SOC monitoring.

        Args:
            interaction: AIInteraction object
            src_ip: Source IP address

        Returns:
            LogEntry for SOC analysis
        """
        return LogEntry(
            timestamp=interaction.timestamp,
            source="real_ai_chatbot",
            message=interaction.prompt,
            agent_id="openai_chatbot_agent",
            user_id=interaction.user_id,
            session_id=interaction.session_id,
            src_ip=src_ip,
            request_id=interaction.interaction_id,
            response_time=interaction.response_time,
            status_code=200,
            extra={
                "agent_type": AgentType.GENERAL.value,
                "ai_response": interaction.response[:200],  # First 200 chars
                "model": interaction.model,
                "tokens_used": interaction.tokens_used,
                "cost": interaction.cost_estimate,
                "security_mode": interaction.metadata.get("security_mode"),
                "real_ai_used": interaction.metadata.get("real_ai_used")
            }
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get AI usage statistics"""
        recent_interactions = self.interaction_log[-100:] if self.interaction_log else []

        avg_response_time = (
            sum(i.response_time for i in recent_interactions) / len(recent_interactions)
            if recent_interactions else 0
        )

        avg_tokens = (
            sum(i.tokens_used for i in recent_interactions) / len(recent_interactions)
            if recent_interactions else 0
        )

        return {
            "total_interactions": len(self.interaction_log),
            "total_tokens_used": self.total_tokens_used,
            "total_cost": round(self.total_cost, 4),
            "average_response_time": round(avg_response_time, 3),
            "average_tokens_per_interaction": round(avg_tokens, 1),
            "model": self.model,
            "real_ai_enabled": self.use_real_ai,
            "recent_interactions_count": len(recent_interactions)
        }

    def get_recent_interactions(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent AI interactions"""
        recent = self.interaction_log[-count:] if self.interaction_log else []
        return [asdict(interaction) for interaction in recent]

    def clear_interaction_log(self):
        """Clear interaction log (useful for testing)"""
        self.interaction_log = []
        self.total_tokens_used = 0
        self.total_cost = 0.0
        self.logger.info("Interaction log cleared")
