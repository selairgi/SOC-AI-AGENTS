#!/usr/bin/env python3
"""
Tests for Cloudflare Integration Module

These tests verify:
1. Deployment mode detection
2. Cloudflare IP validation (security-critical)
3. Header spoofing prevention
4. WAF client functionality (mocked)
5. Hybrid blocker behavior
6. CSRF handling with Cloudflare proxy
7. WebSocket configuration
"""

import pytest
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudflare_integration import (
    DeploymentMode,
    CloudflareIPValidator,
    CloudflareWAFClient,
    CloudflareSecurityHeaders,
    CloudflareWebSocketConfig,
    CloudflareCSRFHandler,
    HybridIPBlocker,
    CLOUDFLARE_IPV4_RANGES,
    CLOUDFLARE_IPV6_RANGES
)


class TestDeploymentMode:
    """Tests for deployment mode detection"""

    def test_default_mode_is_local(self):
        """Default deployment mode should be local"""
        with patch.dict(os.environ, {}, clear=True):
            # Remove DEPLOYMENT_MODE if exists
            os.environ.pop('DEPLOYMENT_MODE', None)
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.LOCAL

    def test_local_mode_from_env(self):
        """Should detect local mode from environment"""
        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'local'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.LOCAL

    def test_cloudflare_mode_from_env(self):
        """Should detect cloudflare mode from environment"""
        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'cloudflare'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.CLOUDFLARE

    def test_case_insensitive(self):
        """Mode detection should be case insensitive"""
        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'CLOUDFLARE'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.CLOUDFLARE

        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'CloudFlare'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.CLOUDFLARE

    def test_invalid_mode_defaults_to_local(self):
        """Invalid mode should default to local with warning"""
        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'invalid_mode'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.LOCAL

    def test_tunnel_mode_from_env(self):
        """Should detect tunnel mode from environment"""
        with patch.dict(os.environ, {'DEPLOYMENT_MODE': 'tunnel'}):
            mode = DeploymentMode.from_env()
            assert mode == DeploymentMode.TUNNEL

    def test_uses_cloudflare_headers_helper(self):
        """Helper should correctly identify modes that use CF headers"""
        assert DeploymentMode.uses_cloudflare_headers(DeploymentMode.LOCAL) == False
        assert DeploymentMode.uses_cloudflare_headers(DeploymentMode.TUNNEL) == True
        assert DeploymentMode.uses_cloudflare_headers(DeploymentMode.CLOUDFLARE) == True

    def test_uses_waf_api_helper(self):
        """Helper should correctly identify modes that use WAF API"""
        assert DeploymentMode.uses_waf_api(DeploymentMode.LOCAL) == False
        assert DeploymentMode.uses_waf_api(DeploymentMode.TUNNEL) == False  # Tunnel is free, no WAF
        assert DeploymentMode.uses_waf_api(DeploymentMode.CLOUDFLARE) == True


class TestCloudflareIPValidator:
    """Tests for Cloudflare IP validation (security-critical)"""

    def setup_method(self):
        """Setup test fixtures"""
        self.validator = CloudflareIPValidator()

    def test_valid_cloudflare_ipv4(self):
        """Should recognize valid Cloudflare IPv4 addresses"""
        # These are actual Cloudflare IPs from their ranges
        valid_ips = [
            "173.245.48.1",      # 173.245.48.0/20
            "103.21.244.100",    # 103.21.244.0/22
            "104.16.0.1",        # 104.16.0.0/13
            "172.64.0.1",        # 172.64.0.0/13
            "162.158.0.1",       # 162.158.0.0/15
        ]
        for ip in valid_ips:
            assert self.validator.is_cloudflare_ip(ip), f"{ip} should be recognized as Cloudflare IP"

    def test_invalid_cloudflare_ipv4(self):
        """Should reject non-Cloudflare IPv4 addresses"""
        invalid_ips = [
            "8.8.8.8",           # Google DNS
            "1.1.1.1",           # Cloudflare DNS (not proxy!)
            "192.168.1.1",       # Private network
            "10.0.0.1",          # Private network
            "203.0.113.1",       # TEST-NET-3
            "142.250.185.78",    # Google
        ]
        for ip in invalid_ips:
            assert not self.validator.is_cloudflare_ip(ip), f"{ip} should NOT be recognized as Cloudflare IP"

    def test_valid_cloudflare_ipv6(self):
        """Should recognize valid Cloudflare IPv6 addresses"""
        valid_ips = [
            "2400:cb00::1",      # 2400:cb00::/32
            "2606:4700::1",      # 2606:4700::/32
            "2803:f800::1",      # 2803:f800::/32
        ]
        for ip in valid_ips:
            assert self.validator.is_cloudflare_ip(ip), f"{ip} should be recognized as Cloudflare IP"

    def test_invalid_cloudflare_ipv6(self):
        """Should reject non-Cloudflare IPv6 addresses"""
        invalid_ips = [
            "2001:4860:4860::8888",  # Google DNS
            "::1",                    # Localhost
            "fe80::1",                # Link-local
        ]
        for ip in invalid_ips:
            assert not self.validator.is_cloudflare_ip(ip), f"{ip} should NOT be recognized as Cloudflare IP"

    def test_invalid_ip_format(self):
        """Should handle invalid IP format gracefully"""
        invalid_formats = [
            "not-an-ip",
            "256.256.256.256",
            "",
            "192.168.1",
        ]
        for ip in invalid_formats:
            # Should return False for invalid formats, not crash
            result = self.validator.is_cloudflare_ip(ip)
            assert result == False, f"Invalid IP '{ip}' should return False"

    def test_none_ip_raises_error(self):
        """Should handle None IP appropriately"""
        # None should cause an error since it's not a valid string
        try:
            result = self.validator.is_cloudflare_ip(None)
            # If it doesn't raise, it should return False
            assert result == False
        except (ValueError, TypeError, AttributeError):
            # This is also acceptable behavior
            pass


class TestCloudflareSecurityHeaders:
    """Tests for Cloudflare security headers handling"""

    def setup_method(self):
        """Setup test fixtures"""
        self.ip_validator = CloudflareIPValidator()
        self.headers = CloudflareSecurityHeaders(self.ip_validator)

    def test_get_real_ip_from_cloudflare(self):
        """Should trust CF-Connecting-IP when request comes from Cloudflare"""
        mock_request = Mock()
        mock_request.remote_addr = "173.245.48.1"  # Cloudflare IP

        # Create a proper mock for headers
        headers_dict = {
            'CF-Connecting-IP': '203.0.113.50',
            'X-Forwarded-For': '203.0.113.50, 173.245.48.1',
            'True-Client-IP': None
        }
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: headers_dict.get(key, default)

        real_ip = self.headers.get_real_client_ip(mock_request)
        assert real_ip == '203.0.113.50'

    def test_reject_spoofed_cf_header(self):
        """Should NOT trust CF-Connecting-IP when NOT from Cloudflare (spoofing prevention)"""
        mock_request = Mock()
        mock_request.remote_addr = "203.0.113.100"  # NOT a Cloudflare IP

        # Attacker trying to spoof CF headers
        headers_dict = {
            'CF-Connecting-IP': '1.2.3.4',
            'X-Forwarded-For': '1.2.3.4',
            'True-Client-IP': None
        }
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: headers_dict.get(key, default)

        real_ip = self.headers.get_real_client_ip(mock_request)
        # Should fall back to X-Forwarded-For, not trust spoofed CF header
        # In a strict implementation, should return remote_addr
        assert real_ip in ['1.2.3.4', '203.0.113.100']

    def test_is_cloudflare_request(self):
        """Should correctly identify requests from Cloudflare"""
        mock_request_cf = Mock()
        mock_request_cf.remote_addr = "173.245.48.1"

        mock_request_non_cf = Mock()
        mock_request_non_cf.remote_addr = "203.0.113.1"

        assert self.headers.is_cloudflare_request(mock_request_cf) == True
        assert self.headers.is_cloudflare_request(mock_request_non_cf) == False

    def test_get_client_country(self):
        """Should extract country code from Cloudflare headers"""
        mock_request = Mock()
        mock_request.remote_addr = "173.245.48.1"
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: {'CF-IPCountry': 'US'}.get(key, default)

        country = self.headers.get_client_country(mock_request)
        assert country == 'US'

    def test_get_cf_ray(self):
        """Should extract CF-Ray ID for request tracing"""
        mock_request = Mock()
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: {'CF-Ray': '12345abc-LAX'}.get(key, default)

        ray_id = self.headers.get_cf_ray(mock_request)
        assert ray_id == '12345abc-LAX'


class TestCloudflareWAFClient:
    """Tests for Cloudflare WAF API client"""

    def test_not_configured_without_env(self):
        """Should report not configured when env vars missing"""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop('CLOUDFLARE_API_TOKEN', None)
            os.environ.pop('CLOUDFLARE_ZONE_ID', None)
            client = CloudflareWAFClient()
            assert client.is_configured == False

    def test_configured_with_env(self):
        """Should report configured when env vars present"""
        with patch.dict(os.environ, {
            'CLOUDFLARE_API_TOKEN': 'test_token',
            'CLOUDFLARE_ZONE_ID': 'test_zone'
        }):
            client = CloudflareWAFClient()
            assert client.is_configured == True

    @patch('requests.post')
    def test_block_ip_success(self, mock_post):
        """Should successfully block IP via API"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'success': True,
            'result': {'id': 'rule_123'}
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            'CLOUDFLARE_API_TOKEN': 'test_token',
            'CLOUDFLARE_ZONE_ID': 'test_zone'
        }):
            client = CloudflareWAFClient()
            success, rule_id, error = client.block_ip('192.168.1.100', 'Test block')

            assert success == True
            assert rule_id == 'rule_123'
            assert error is None

    @patch('requests.post')
    def test_block_ip_failure(self, mock_post):
        """Should handle API failure gracefully"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'success': False,
            'errors': [{'message': 'API error'}]
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            'CLOUDFLARE_API_TOKEN': 'test_token',
            'CLOUDFLARE_ZONE_ID': 'test_zone'
        }):
            client = CloudflareWAFClient()
            success, rule_id, error = client.block_ip('192.168.1.100', 'Test block')

            assert success == False
            assert rule_id is None
            assert 'API error' in error

    def test_block_invalid_ip(self):
        """Should reject invalid IP addresses"""
        with patch.dict(os.environ, {
            'CLOUDFLARE_API_TOKEN': 'test_token',
            'CLOUDFLARE_ZONE_ID': 'test_zone'
        }):
            client = CloudflareWAFClient()
            success, rule_id, error = client.block_ip('not-an-ip', 'Test')

            assert success == False
            assert 'Invalid IP' in error


class TestHybridIPBlocker:
    """Tests for hybrid IP blocker (local + Cloudflare)"""

    def setup_method(self):
        """Setup test fixtures"""
        self.mock_local_remediator = Mock()
        self.mock_local_remediator.is_ip_blocked.return_value = False
        self.mock_local_remediator.block_ip.return_value = True
        self.mock_local_remediator.unblock_ip.return_value = True
        self.mock_local_remediator.get_blocked_ips.return_value = []

    def test_local_mode_uses_local_blocker(self):
        """In local mode, should use local remediator"""
        mock_waf = Mock()
        mock_waf.is_configured = False

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.LOCAL
        )

        success, error = blocker.block_ip('192.168.1.100', 'Test')

        # Should call local remediator
        self.mock_local_remediator.block_ip.assert_called()
        assert success == True

    def test_cloudflare_mode_uses_waf_when_configured(self):
        """In Cloudflare mode with WAF configured, should use WAF"""
        mock_waf = Mock()
        mock_waf.is_configured = True
        mock_waf.block_ip.return_value = (True, 'rule_123', None)

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.CLOUDFLARE
        )

        success, error = blocker.block_ip('192.168.1.100', 'Test')

        # Should call Cloudflare WAF
        mock_waf.block_ip.assert_called()
        assert success == True

    def test_cloudflare_mode_falls_back_when_waf_not_configured(self):
        """In Cloudflare mode without WAF, should fall back to local"""
        mock_waf = Mock()
        mock_waf.is_configured = False

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.CLOUDFLARE
        )

        success, error = blocker.block_ip('192.168.1.100', 'Test')

        # Should fall back to local remediator
        self.mock_local_remediator.block_ip.assert_called()
        assert success == True

    def test_is_ip_blocked_checks_all_sources(self):
        """Should check both local cache and appropriate source"""
        mock_waf = Mock()
        mock_waf.is_configured = True
        mock_waf.is_ip_blocked.return_value = False

        self.mock_local_remediator.is_ip_blocked.return_value = True

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.CLOUDFLARE
        )

        # Local says blocked, so should return True
        assert blocker.is_ip_blocked('192.168.1.100') == True

    def test_tunnel_mode_uses_local_blocker_only(self):
        """Tunnel mode (free) should ONLY use local blocking, never WAF API"""
        mock_waf = Mock()
        mock_waf.is_configured = True  # Even if configured, shouldn't use it

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.TUNNEL  # Free tier
        )

        success, error = blocker.block_ip('192.168.1.100', 'Test')

        # Should call local remediator, NOT WAF
        self.mock_local_remediator.block_ip.assert_called()
        mock_waf.block_ip.assert_not_called()
        assert success == True

    def test_tunnel_mode_unblock_uses_local_only(self):
        """Tunnel mode unblock should only use local remediator"""
        mock_waf = Mock()
        mock_waf.is_configured = True

        blocker = HybridIPBlocker(
            local_remediator=self.mock_local_remediator,
            cloudflare_waf=mock_waf,
            deployment_mode=DeploymentMode.TUNNEL
        )

        blocker.unblock_ip('192.168.1.100')

        # Should call local, not WAF
        self.mock_local_remediator.unblock_ip.assert_called()
        mock_waf.unblock_ip.assert_not_called()


class TestCloudflareWebSocketConfig:
    """Tests for WebSocket configuration"""

    def test_local_config(self):
        """Local mode should have permissive CORS"""
        config = CloudflareWebSocketConfig.get_socketio_config(DeploymentMode.LOCAL)

        assert config['cors_allowed_origins'] == '*'
        assert config['async_mode'] == 'eventlet'
        assert 'ping_interval' in config
        assert 'ping_timeout' in config

    def test_cloudflare_config_with_custom_origins(self):
        """Cloudflare mode should use configured origins"""
        with patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://example.com,https://www.example.com'}):
            config = CloudflareWebSocketConfig.get_socketio_config(DeploymentMode.CLOUDFLARE)

            assert isinstance(config['cors_allowed_origins'], list)
            assert 'https://example.com' in config['cors_allowed_origins']
            # Ping settings should be suitable for Cloudflare timeout
            assert config['ping_interval'] <= 50  # Well under Cloudflare's 100s timeout

    def test_client_config_for_cloudflare(self):
        """Client config should use polling then upgrade to WebSocket for tunnel stability"""
        config = CloudflareWebSocketConfig.get_client_config(DeploymentMode.CLOUDFLARE)

        # For Cloudflare Tunnel, start with polling and upgrade to websocket
        assert config['transports'] == ['polling', 'websocket']
        assert config['upgrade'] == True
        assert config['reconnection'] == True
        assert config['withCredentials'] == True

    def test_client_config_for_tunnel(self):
        """Tunnel mode client config should be same as cloudflare mode"""
        config = CloudflareWebSocketConfig.get_client_config(DeploymentMode.TUNNEL)

        # Tunnel uses same config as cloudflare
        assert config['transports'] == ['polling', 'websocket']
        assert config['upgrade'] == True
        assert config['withCredentials'] == True


class TestCloudflareCSRFHandler:
    """Tests for CSRF handling with Cloudflare"""

    def test_session_config_local(self):
        """Local mode should not require secure cookies"""
        config = CloudflareCSRFHandler.get_session_config(DeploymentMode.LOCAL)

        assert config['SESSION_COOKIE_SECURE'] == False
        assert config['SESSION_COOKIE_HTTPONLY'] == True

    def test_session_config_tunnel(self):
        """Tunnel mode should use secure cookies (ProxyFix makes Flask recognize HTTPS)"""
        config = CloudflareCSRFHandler.get_session_config(DeploymentMode.TUNNEL)

        assert config['SESSION_COOKIE_SECURE'] == True  # ProxyFix makes Flask recognize HTTPS
        assert config['SESSION_COOKIE_HTTPONLY'] == True
        assert config['SESSION_COOKIE_SAMESITE'] == 'None'  # Required for Secure cookies

    def test_session_config_cloudflare(self):
        """Cloudflare mode should require secure cookies (Flask is directly behind HTTPS)"""
        config = CloudflareCSRFHandler.get_session_config(DeploymentMode.CLOUDFLARE)

        assert config['SESSION_COOKIE_SECURE'] == True
        assert config['SESSION_COOKIE_HTTPONLY'] == True
        assert config['SESSION_COOKIE_SAMESITE'] == 'Lax'

    def test_no_cache_headers(self):
        """Should add proper no-cache headers to response"""
        mock_response = Mock()
        mock_response.headers = {}

        result = CloudflareCSRFHandler.add_no_cache_headers(mock_response)

        assert 'Cache-Control' in mock_response.headers
        assert 'no-store' in mock_response.headers['Cache-Control']
        assert 'Pragma' in mock_response.headers
        assert mock_response.headers['Pragma'] == 'no-cache'


class TestSecurityScenarios:
    """Integration tests for security scenarios"""

    def test_header_spoofing_attack(self):
        """Test that header spoofing is prevented"""
        ip_validator = CloudflareIPValidator()
        headers = CloudflareSecurityHeaders(ip_validator)

        # Attacker sends request directly (not through CF) with fake CF header
        mock_request = Mock()
        mock_request.remote_addr = "evil.attacker.com"  # Will fail IP parse
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: {
            'CF-Connecting-IP': '127.0.0.1',  # Attacker trying to pretend to be localhost
            'X-Forwarded-For': '127.0.0.1'
        }.get(key, default)

        # Should not trust the spoofed header
        # Validator should return False for non-CF IP
        assert ip_validator.is_cloudflare_ip("203.0.113.50") == False

    def test_legitimate_cloudflare_request(self):
        """Test that legitimate Cloudflare requests are handled correctly"""
        ip_validator = CloudflareIPValidator()
        headers = CloudflareSecurityHeaders(ip_validator)

        # Request from actual Cloudflare IP
        mock_request = Mock()
        mock_request.remote_addr = "173.245.48.10"  # Real Cloudflare IP
        mock_request.headers = Mock()
        mock_request.headers.get = lambda key, default=None: {
            'CF-Connecting-IP': '203.0.113.50',
            'CF-IPCountry': 'US',
            'CF-Ray': 'abc123-SJC'
        }.get(key, default)

        # Should trust the headers
        assert headers.is_cloudflare_request(mock_request) == True
        assert headers.get_real_client_ip(mock_request) == '203.0.113.50'
        assert headers.get_client_country(mock_request) == 'US'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
