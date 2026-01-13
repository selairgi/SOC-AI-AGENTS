#!/usr/bin/env python3
"""
Cloudflare Integration Module for SOC AI Agents

This module provides:
1. Deployment mode detection (local vs cloudflare)
2. Cloudflare IP validation (prevent header spoofing)
3. Cloudflare WAF API integration for IP blocking
4. WebSocket configuration for Cloudflare proxy
5. Security headers validation
"""

import os
import re
import logging
import ipaddress
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import json
import hashlib
import hmac

import requests
from flask import request

logger = logging.getLogger("CloudflareIntegration")


# Cloudflare IP ranges (updated periodically)
# Source: https://www.cloudflare.com/ips/
CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CLOUDFLARE_IPV6_RANGES = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]


class DeploymentMode:
    """
    Deployment mode enum-like class

    Modes:
    - LOCAL: Development mode, no Cloudflare (uses X-Forwarded-For or remote_addr)
    - TUNNEL: Cloudflare Tunnel (free) - validates CF headers, blocks IPs locally
    - CLOUDFLARE: Full Cloudflare with WAF API (paid) - blocks IPs at edge via API
    """
    LOCAL = "local"
    TUNNEL = "tunnel"  # Free Cloudflare Tunnel - local blocking
    CLOUDFLARE = "cloudflare"  # Paid Cloudflare with WAF API

    @classmethod
    def from_env(cls) -> str:
        """Get deployment mode from environment"""
        mode = os.getenv("DEPLOYMENT_MODE", "local").lower()
        if mode not in [cls.LOCAL, cls.TUNNEL, cls.CLOUDFLARE]:
            logger.warning(f"Invalid DEPLOYMENT_MODE '{mode}', defaulting to 'local'")
            return cls.LOCAL
        return mode

    @classmethod
    def uses_cloudflare_headers(cls, mode: str) -> bool:
        """Check if this mode uses Cloudflare headers (tunnel or full cloudflare)"""
        return mode in [cls.TUNNEL, cls.CLOUDFLARE]

    @classmethod
    def uses_waf_api(cls, mode: str) -> bool:
        """Check if this mode uses Cloudflare WAF API (only full cloudflare)"""
        return mode == cls.CLOUDFLARE


class CloudflareIPValidator:
    """Validates that requests actually come from Cloudflare"""

    def __init__(self):
        self._ipv4_networks = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4_RANGES]
        self._ipv6_networks = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV6_RANGES]
        self._last_refresh = datetime.now(timezone.utc)
        self._refresh_interval = timedelta(hours=24)

    def is_cloudflare_ip(self, ip: str) -> bool:
        """
        Check if an IP address belongs to Cloudflare's network.

        This is CRITICAL for security - we only trust CF-Connecting-IP
        if the request comes from a Cloudflare IP.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            if isinstance(ip_obj, ipaddress.IPv4Address):
                return any(ip_obj in network for network in self._ipv4_networks)
            else:
                return any(ip_obj in network for network in self._ipv6_networks)
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip}")
            return False

    def refresh_cloudflare_ips(self) -> bool:
        """
        Refresh Cloudflare IP ranges from their API.
        Call this periodically (e.g., daily) to keep ranges updated.
        """
        try:
            # Fetch IPv4 ranges
            response = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
            if response.status_code == 200:
                ipv4_ranges = [line.strip() for line in response.text.strip().split('\n') if line.strip()]
                self._ipv4_networks = [ipaddress.ip_network(cidr) for cidr in ipv4_ranges]

            # Fetch IPv6 ranges
            response = requests.get("https://www.cloudflare.com/ips-v6", timeout=10)
            if response.status_code == 200:
                ipv6_ranges = [line.strip() for line in response.text.strip().split('\n') if line.strip()]
                self._ipv6_networks = [ipaddress.ip_network(cidr) for cidr in ipv6_ranges]

            self._last_refresh = datetime.now(timezone.utc)
            logger.info("Cloudflare IP ranges refreshed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to refresh Cloudflare IP ranges: {e}")
            return False


class CloudflareWAFClient:
    """
    Client for Cloudflare WAF API to manage IP blocking via Access Rules.

    Required environment variables:
    - CLOUDFLARE_API_TOKEN: API token with Zone.Firewall Services permissions
    - CLOUDFLARE_ZONE_ID: Your zone ID (found in Cloudflare dashboard)
    - CLOUDFLARE_ACCOUNT_ID: Your account ID (optional, for account-level rules)
    """

    API_BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self):
        self.api_token = os.getenv("CLOUDFLARE_API_TOKEN")
        self.zone_id = os.getenv("CLOUDFLARE_ZONE_ID")
        self.account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")

        if not self.api_token:
            logger.warning("CLOUDFLARE_API_TOKEN not set - WAF blocking will be disabled")
        if not self.zone_id:
            logger.warning("CLOUDFLARE_ZONE_ID not set - Zone-level WAF rules disabled")

        self._headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        # Cache for blocked IPs (to reduce API calls)
        self._blocked_ips_cache: Dict[str, Dict] = {}
        self._cache_ttl = timedelta(minutes=5)
        self._last_cache_refresh = datetime.min

    @property
    def is_configured(self) -> bool:
        """Check if Cloudflare WAF is properly configured"""
        return bool(self.api_token and self.zone_id)

    def block_ip(
        self,
        ip: str,
        reason: str = "Blocked by SOC AI Agents",
        duration: Optional[int] = None,
        mode: str = "block"
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Block an IP address using Cloudflare WAF Access Rules.

        Args:
            ip: IP address to block
            reason: Reason for blocking (stored as note)
            duration: Duration in seconds (None = permanent until manual unblock)
            mode: "block" (403), "challenge" (CAPTCHA), or "js_challenge" (JS challenge)

        Returns:
            (success, rule_id, error_message)
        """
        if not self.is_configured:
            return False, None, "Cloudflare WAF not configured"

        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, None, f"Invalid IP address: {ip}"

        # Check if already blocked
        existing_rule = self._get_existing_rule(ip)
        if existing_rule:
            logger.info(f"IP {ip} is already blocked (rule: {existing_rule['id']})")
            return True, existing_rule['id'], None

        # Create access rule
        try:
            url = f"{self.API_BASE}/zones/{self.zone_id}/firewall/access_rules/rules"

            payload = {
                "mode": mode,
                "configuration": {
                    "target": "ip",
                    "value": ip
                },
                "notes": f"{reason} | Blocked at: {datetime.now(timezone.utc).isoformat()} | Duration: {duration or 'permanent'}s"
            }

            response = requests.post(url, headers=self._headers, json=payload, timeout=30)
            result = response.json()

            if result.get("success"):
                rule_id = result["result"]["id"]
                logger.info(f"Blocked IP {ip} via Cloudflare WAF (rule: {rule_id})")

                # Update cache
                self._blocked_ips_cache[ip] = {
                    "rule_id": rule_id,
                    "blocked_at": datetime.now(timezone.utc),
                    "duration": duration,
                    "reason": reason
                }

                # Schedule unblock if duration is set
                if duration:
                    self._schedule_unblock(ip, rule_id, duration)

                return True, rule_id, None
            else:
                errors = result.get("errors", [])
                error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
                logger.error(f"Failed to block IP {ip}: {error_msg}")
                return False, None, error_msg

        except requests.RequestException as e:
            logger.error(f"Cloudflare API request failed: {e}")
            return False, None, str(e)

    def unblock_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Unblock an IP address by removing its Cloudflare WAF rule.

        Returns:
            (success, error_message)
        """
        if not self.is_configured:
            return False, "Cloudflare WAF not configured"

        # Find existing rule
        rule = self._get_existing_rule(ip)
        if not rule:
            logger.info(f"IP {ip} is not currently blocked in Cloudflare WAF")
            return True, None

        try:
            url = f"{self.API_BASE}/zones/{self.zone_id}/firewall/access_rules/rules/{rule['id']}"

            response = requests.delete(url, headers=self._headers, timeout=30)
            result = response.json()

            if result.get("success"):
                logger.info(f"Unblocked IP {ip} from Cloudflare WAF (rule: {rule['id']})")

                # Update cache
                if ip in self._blocked_ips_cache:
                    del self._blocked_ips_cache[ip]

                return True, None
            else:
                errors = result.get("errors", [])
                error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
                return False, error_msg

        except requests.RequestException as e:
            logger.error(f"Cloudflare API request failed: {e}")
            return False, str(e)

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Get list of all blocked IPs from Cloudflare WAF.

        Returns list of dicts with ip, rule_id, mode, notes
        """
        if not self.is_configured:
            return []

        # Check cache
        if datetime.now(timezone.utc) - self._last_cache_refresh < self._cache_ttl:
            return [
                {"ip": ip, **data}
                for ip, data in self._blocked_ips_cache.items()
            ]

        try:
            blocked_ips = []
            page = 1
            per_page = 50

            while True:
                url = f"{self.API_BASE}/zones/{self.zone_id}/firewall/access_rules/rules"
                params = {
                    "mode": "block",
                    "page": page,
                    "per_page": per_page
                }

                response = requests.get(url, headers=self._headers, params=params, timeout=30)
                result = response.json()

                if not result.get("success"):
                    break

                rules = result.get("result", [])
                if not rules:
                    break

                for rule in rules:
                    config = rule.get("configuration", {})
                    if config.get("target") == "ip":
                        ip = config.get("value")
                        blocked_ips.append({
                            "ip": ip,
                            "rule_id": rule["id"],
                            "mode": rule.get("mode"),
                            "notes": rule.get("notes", ""),
                            "created_on": rule.get("created_on")
                        })

                        # Update cache
                        self._blocked_ips_cache[ip] = {
                            "rule_id": rule["id"],
                            "mode": rule.get("mode"),
                            "notes": rule.get("notes", "")
                        }

                # Check if there are more pages
                result_info = result.get("result_info", {})
                total_pages = result_info.get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            self._last_cache_refresh = datetime.now(timezone.utc)
            return blocked_ips

        except requests.RequestException as e:
            logger.error(f"Failed to fetch blocked IPs from Cloudflare: {e}")
            return []

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked in Cloudflare WAF"""
        # Quick cache check
        if ip in self._blocked_ips_cache:
            return True

        # Full check
        rule = self._get_existing_rule(ip)
        return rule is not None

    def _get_existing_rule(self, ip: str) -> Optional[Dict]:
        """Get existing access rule for an IP"""
        if not self.is_configured:
            return None

        try:
            url = f"{self.API_BASE}/zones/{self.zone_id}/firewall/access_rules/rules"
            params = {
                "configuration.target": "ip",
                "configuration.value": ip
            }

            response = requests.get(url, headers=self._headers, params=params, timeout=30)
            result = response.json()

            if result.get("success") and result.get("result"):
                return result["result"][0]
            return None

        except requests.RequestException as e:
            logger.error(f"Failed to check existing rule: {e}")
            return None

    def _schedule_unblock(self, ip: str, rule_id: str, duration: int):
        """
        Schedule automatic unblock after duration.

        Note: For production, use a proper task queue (Celery, APScheduler, etc.)
        This is a basic implementation using threading.
        """
        import threading

        def unblock_after_delay():
            import time
            time.sleep(duration)
            self.unblock_ip(ip)
            logger.info(f"Auto-unblocked IP {ip} after {duration}s")

        thread = threading.Thread(target=unblock_after_delay, daemon=True)
        thread.start()

    def challenge_ip(self, ip: str, reason: str = "Challenge required by SOC") -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Set CAPTCHA challenge for an IP instead of blocking.
        Useful for suspicious but not confirmed malicious traffic.
        """
        return self.block_ip(ip, reason, mode="challenge")

    def js_challenge_ip(self, ip: str, reason: str = "JS Challenge by SOC") -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Set JavaScript challenge for an IP.
        Less intrusive than CAPTCHA, blocks basic bots.
        """
        return self.block_ip(ip, reason, mode="js_challenge")


class CloudflareSecurityHeaders:
    """Validates and extracts security-relevant Cloudflare headers"""

    # Cloudflare header names
    CF_CONNECTING_IP = "CF-Connecting-IP"
    CF_IPCOUNTRY = "CF-IPCountry"
    CF_RAY = "CF-Ray"
    CF_VISITOR = "CF-Visitor"
    CF_WORKER = "CF-Worker"
    CF_WARP_TAG_ID = "CF-Warp-Tag-ID"
    TRUE_CLIENT_IP = "True-Client-IP"  # Enterprise only

    def __init__(self, ip_validator: CloudflareIPValidator):
        self.ip_validator = ip_validator

    def get_real_client_ip(self, flask_request) -> str:
        """
        Get the real client IP address, validating Cloudflare headers.

        Security: Only trusts CF-Connecting-IP if the request comes from
        a verified Cloudflare IP. Otherwise, falls back to X-Forwarded-For
        or remote_addr.
        """
        # Get the immediate connecting IP (might be Cloudflare proxy)
        connecting_ip = flask_request.remote_addr

        # If request comes from Cloudflare, trust their headers
        if self.ip_validator.is_cloudflare_ip(connecting_ip):
            # CF-Connecting-IP is the most reliable
            cf_ip = flask_request.headers.get(self.CF_CONNECTING_IP)
            if cf_ip:
                return cf_ip

            # Enterprise customers might have True-Client-IP
            true_client_ip = flask_request.headers.get(self.TRUE_CLIENT_IP)
            if true_client_ip:
                return true_client_ip

        # Not from Cloudflare - check standard proxy headers with caution
        forwarded_for = flask_request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (leftmost = original client)
            # But only if we're behind a trusted proxy
            return forwarded_for.split(",")[0].strip()

        # Fall back to direct connection IP
        return connecting_ip

    def get_client_country(self, flask_request) -> Optional[str]:
        """Get client country from Cloudflare (2-letter ISO code)"""
        connecting_ip = flask_request.remote_addr
        if self.ip_validator.is_cloudflare_ip(connecting_ip):
            return flask_request.headers.get(self.CF_IPCOUNTRY)
        return None

    def get_cf_ray(self, flask_request) -> Optional[str]:
        """Get Cloudflare Ray ID for request tracing"""
        return flask_request.headers.get(self.CF_RAY)

    def is_cloudflare_request(self, flask_request) -> bool:
        """Check if request is coming through Cloudflare"""
        connecting_ip = flask_request.remote_addr
        return self.ip_validator.is_cloudflare_ip(connecting_ip)

    def get_visitor_scheme(self, flask_request) -> Optional[str]:
        """Get visitor's original protocol (http/https) from CF-Visitor header"""
        cf_visitor = flask_request.headers.get(self.CF_VISITOR)
        if cf_visitor:
            try:
                data = json.loads(cf_visitor)
                return data.get("scheme")
            except (json.JSONDecodeError, TypeError):
                pass
        return None


class CloudflareWebSocketConfig:
    """
    Configuration helper for WebSocket connections through Cloudflare.

    Cloudflare has specific requirements for WebSocket connections:
    1. WebSocket must be enabled in Cloudflare dashboard
    2. Connections upgrade from HTTPS to WSS
    3. Timeouts need to be configured properly
    4. SSL mode should be "Full" or "Full (strict)"
    """

    @staticmethod
    def get_socketio_config(deployment_mode: str) -> Dict[str, Any]:
        """
        Get SocketIO configuration based on deployment mode.

        For Cloudflare (Tunnel or full):
        - Longer ping intervals (Cloudflare has 100s timeout)
        - Proper CORS for your domain
        - WebSocket transport with polling fallback
        """
        # Both TUNNEL and CLOUDFLARE modes go through Cloudflare proxy
        if DeploymentMode.uses_cloudflare_headers(deployment_mode):
            allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
            if allowed_origins != "*":
                allowed_origins = [origin.strip() for origin in allowed_origins.split(",")]

            return {
                "cors_allowed_origins": allowed_origins,
                "async_mode": "eventlet",
                # Cloudflare Tunnel timeout settings
                # Keep ping well below Cloudflare's 100s idle timeout
                "ping_interval": 10,  # Reduced for tunnel stability
                "ping_timeout": 20,
                # CRITICAL for Cloudflare Tunnel:
                # Must allow upgrades and support both transports
                "allow_upgrades": True,
                "transports": ["polling", "websocket"],  # Start with polling, upgrade to WS
                # Disable manage_session to let Flask handle sessions
                # This fixes the 400 errors on polling POST
                "manage_session": False,
                # Increase max HTTP buffer for large messages
                "max_http_buffer_size": 1024 * 1024,  # 1MB
                # Enable logging for debugging tunnel issues
                "engineio_logger": True,
                "logger": True
            }
        else:
            # Local development settings
            return {
                "cors_allowed_origins": "*",
                "async_mode": "eventlet",
                "ping_interval": 25,
                "ping_timeout": 60,
                "manage_session": False
            }

    @staticmethod
    def get_client_config(deployment_mode: str) -> Dict[str, Any]:
        """
        Get client-side Socket.IO configuration.
        Returns config to be passed to frontend.
        """
        # Both TUNNEL and CLOUDFLARE modes need specific config for stability
        if DeploymentMode.uses_cloudflare_headers(deployment_mode):
            return {
                # Start with polling, then upgrade to WebSocket
                # This is more reliable through Cloudflare Tunnel
                "transports": ["polling", "websocket"],
                "upgrade": True,  # Allow upgrade from polling to websocket
                "forceNew": True,
                "reconnection": True,
                "reconnectionAttempts": 10,  # Limit attempts to avoid infinite loops
                "reconnectionDelay": 1000,
                "reconnectionDelayMax": 5000,
                "timeout": 20000,
                # Important for session handling
                "withCredentials": True
            }
        else:
            return {
                "transports": ["websocket", "polling"],
                "upgrade": True,
                "forceNew": True,
                "reconnection": True,
                "reconnectionAttempts": "Infinity"
            }


class HybridIPBlocker:
    """
    Hybrid IP blocker that works in all deployment modes.

    - LOCAL mode: Uses local middleware blocking
    - TUNNEL mode: Uses local blocking (Cloudflare Tunnel is free, no WAF API)
    - CLOUDFLARE mode: Uses Cloudflare WAF API (paid tier)
    """

    def __init__(self, local_remediator, cloudflare_waf: CloudflareWAFClient, deployment_mode: str):
        self.local_remediator = local_remediator
        self.cloudflare_waf = cloudflare_waf
        self.deployment_mode = deployment_mode

        # Also maintain local cache for faster checks
        self._local_block_cache: Dict[str, Dict] = {}

    def block_ip(
        self,
        ip: str,
        reason: str = "Security threat detected",
        duration: int = 3600,
        alert_id: str = "auto"
    ) -> Tuple[bool, Optional[str]]:
        """
        Block an IP address using the appropriate method based on deployment mode.

        Returns: (success, error_message)
        """
        # Only use WAF API in full Cloudflare mode (paid)
        if DeploymentMode.uses_waf_api(self.deployment_mode):
            if self.cloudflare_waf.is_configured:
                success, rule_id, error = self.cloudflare_waf.block_ip(ip, reason, duration)
                if success:
                    # Also add to local cache for immediate effect
                    self._local_block_cache[ip] = {
                        "blocked_at": datetime.now(timezone.utc),
                        "reason": reason,
                        "rule_id": rule_id
                    }
                return success, error
            else:
                logger.warning("Cloudflare WAF not configured, falling back to local blocking")

        # Local/Tunnel mode or WAF fallback - use local blocking
        # This works perfectly with Cloudflare Tunnel since we get the real IP via CF-Connecting-IP
        if self.local_remediator:
            self.local_remediator.block_ip(ip, reason, duration, alert_id)
            self._local_block_cache[ip] = {
                "blocked_at": datetime.now(timezone.utc),
                "reason": reason
            }
            return True, None

        return False, "No blocking mechanism available"

    def unblock_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Unblock an IP address"""
        errors = []

        # Only try WAF API in full Cloudflare mode
        if DeploymentMode.uses_waf_api(self.deployment_mode):
            if self.cloudflare_waf.is_configured:
                success, error = self.cloudflare_waf.unblock_ip(ip)
                if not success and error:
                    errors.append(f"Cloudflare: {error}")

        # Always try local unblock too
        if self.local_remediator:
            try:
                self.local_remediator.unblock_ip(ip)
            except Exception as e:
                errors.append(f"Local: {str(e)}")

        # Remove from cache
        if ip in self._local_block_cache:
            del self._local_block_cache[ip]

        return len(errors) == 0, "; ".join(errors) if errors else None

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked (checks both local and Cloudflare)"""
        # Quick local cache check
        if ip in self._local_block_cache:
            return True

        # Check local remediator
        if self.local_remediator and self.local_remediator.is_ip_blocked(ip):
            return True

        # Check Cloudflare (if configured)
        if self.deployment_mode == DeploymentMode.CLOUDFLARE and self.cloudflare_waf.is_configured:
            return self.cloudflare_waf.is_ip_blocked(ip)

        return False

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get all blocked IPs from all sources"""
        blocked = []

        # Get from Cloudflare WAF (only in full cloudflare mode)
        if DeploymentMode.uses_waf_api(self.deployment_mode) and self.cloudflare_waf.is_configured:
            cf_blocked = self.cloudflare_waf.get_blocked_ips()
            for item in cf_blocked:
                item["source"] = "cloudflare_waf"
            blocked.extend(cf_blocked)

        # Get from local remediator
        if self.local_remediator:
            local_blocked = self.local_remediator.get_blocked_ips()
            for item in local_blocked:
                if isinstance(item, dict):
                    item["source"] = "local"
                    blocked.append(item)
                else:
                    blocked.append({"ip": item, "source": "local"})

        return blocked


class CloudflareCSRFHandler:
    """
    Enhanced CSRF handling for Cloudflare deployment.

    Considerations:
    1. Cloudflare may cache responses - ensure CSRF endpoints aren't cached
    2. WebSocket connections need token validation
    3. SameSite cookie handling with proxy
    """

    CACHE_CONTROL_HEADERS = {
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    @staticmethod
    def get_session_config(deployment_mode: str) -> Dict[str, Any]:
        """Get Flask session configuration based on deployment mode"""
        base_config = {
            "SESSION_COOKIE_HTTPONLY": True,
            "PERMANENT_SESSION_LIFETIME": timedelta(hours=8)
        }

        # Full Cloudflare mode: Flask is directly behind Cloudflare with HTTPS
        if deployment_mode == DeploymentMode.CLOUDFLARE:
            base_config.update({
                "SESSION_COOKIE_SECURE": True,  # Cloudflare provides HTTPS to Flask
                "SESSION_COOKIE_SAMESITE": "Lax",
                # Set domain if using subdomain
                # "SESSION_COOKIE_DOMAIN": os.getenv("COOKIE_DOMAIN")
            })
        # Tunnel mode: Flask runs on HTTP locally, Cloudflare Tunnel provides HTTPS externally
        # ProxyFix middleware makes Flask recognize HTTPS via X-Forwarded-Proto header
        elif deployment_mode == DeploymentMode.TUNNEL:
            base_config.update({
                "SESSION_COOKIE_SECURE": True,  # Required for HTTPS (ProxyFix makes Flask recognize it)
                "SESSION_COOKIE_SAMESITE": "None",  # Required for cross-site cookie with Secure flag
            })
        else:
            # Local development
            base_config.update({
                "SESSION_COOKIE_SECURE": False,
                "SESSION_COOKIE_SAMESITE": "Lax"
            })

        return base_config

    @staticmethod
    def add_no_cache_headers(response):
        """Add headers to prevent caching of CSRF-sensitive responses"""
        for header, value in CloudflareCSRFHandler.CACHE_CONTROL_HEADERS.items():
            response.headers[header] = value
        return response


# Initialize global instances
_ip_validator: Optional[CloudflareIPValidator] = None
_waf_client: Optional[CloudflareWAFClient] = None
_security_headers: Optional[CloudflareSecurityHeaders] = None


def get_ip_validator() -> CloudflareIPValidator:
    """Get or create the IP validator singleton"""
    global _ip_validator
    if _ip_validator is None:
        _ip_validator = CloudflareIPValidator()
    return _ip_validator


def get_waf_client() -> CloudflareWAFClient:
    """Get or create the WAF client singleton"""
    global _waf_client
    if _waf_client is None:
        _waf_client = CloudflareWAFClient()
    return _waf_client


def get_security_headers() -> CloudflareSecurityHeaders:
    """Get or create the security headers handler singleton"""
    global _security_headers
    if _security_headers is None:
        _security_headers = CloudflareSecurityHeaders(get_ip_validator())
    return _security_headers


def get_real_client_ip() -> str:
    """
    Convenience function to get real client IP from current Flask request.
    Handles both local and Cloudflare deployments securely.
    """
    deployment_mode = DeploymentMode.from_env()

    if deployment_mode == DeploymentMode.CLOUDFLARE:
        return get_security_headers().get_real_client_ip(request)
    else:
        # Local mode - still check for proxies
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr


def create_hybrid_blocker(local_remediator) -> HybridIPBlocker:
    """Create a hybrid IP blocker instance"""
    return HybridIPBlocker(
        local_remediator=local_remediator,
        cloudflare_waf=get_waf_client(),
        deployment_mode=DeploymentMode.from_env()
    )
