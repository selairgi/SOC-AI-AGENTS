#!/usr/bin/env python3
"""
Quick test to verify OpenAI connection is working
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
import json

BASE_URL = "http://localhost:5000"

def test_chat():
    """Test a simple chat message"""
    try:
        # Get session
        response = requests.get(f"{BASE_URL}/")
        cookies = response.cookies

        # Send test message
        response = requests.post(
            f"{BASE_URL}/api/chat",
            json={
                "message": "Hello, what is 2+2?",
                "user_id": "test_user",
                "session_id": "test_session",
                "security_mode": "security_aware"
            },
            cookies=cookies,
            headers={
                "Content-Type": "application/json",
                "X-CSRFToken": "test_token"
            },
            timeout=35
        )

        if response.status_code == 200:
            result = response.json()
            print("✓ OpenAI connection working!")
            print(f"\nAI Response: {result.get('response', 'N/A')}")

            security = result.get('security_check', {})
            print(f"\nSecurity Check:")
            print(f"  Alert Detected: {security.get('alert_detected', False)}")
            print(f"  Blocked: {security.get('blocked', False)}")
            return True
        else:
            print(f"✗ HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing OpenAI connection with timeout fix...\n")
    test_chat()
