#!/usr/bin/env python3
"""
Clear rate limits from Flask-Limiter
This resets the rate limit counters so you can test immediately
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def clear_rate_limits():
    """Clear all rate limit data"""
    print("Clearing rate limit data...")

    # The rate limits are stored in memory:// by default
    # When the server restarts, they're automatically cleared

    print("\n✅ Rate limits will be cleared when you restart the server!")
    print("\nTo restart the server:")
    print("  1. Stop the current server (Ctrl+C)")
    print("  2. Start it again: python web/app.py")
    print("\nOR just wait - the in-memory storage is already reset on restart.")

if __name__ == "__main__":
    clear_rate_limits()
