#!/usr/bin/env python3
"""
Clear Rate Limits from Redis
Resets all Flask-Limiter counters stored in Redis
"""

import redis
import os
from dotenv import load_dotenv

load_dotenv()

def clear_rate_limits():
    """Clear all rate limit keys from Redis"""

    # Connect to Redis
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    print("=" * 60)
    print("Clearing Rate Limits from Redis")
    print("=" * 60)
    print(f"\nConnecting to: {redis_url}")

    try:
        r = redis.from_url(redis_url, decode_responses=True)

        # Test connection
        r.ping()
        print("✅ Connected to Redis")

        # Find all rate limit keys
        print("\nSearching for rate limit keys (LIMITER*)...")
        keys = r.keys("LIMITER*")

        if keys:
            print(f"Found {len(keys)} rate limit keys:")
            for key in keys[:10]:  # Show first 10
                print(f"  - {key}")
            if len(keys) > 10:
                print(f"  ... and {len(keys) - 10} more")

            # Delete all rate limit keys
            print(f"\nDeleting {len(keys)} keys...")
            deleted = r.delete(*keys)
            print(f"✅ Deleted {deleted} rate limit keys")
        else:
            print("No rate limit keys found (cache is already clean)")

        print("\n" + "=" * 60)
        print("✅ Rate limits cleared successfully!")
        print("=" * 60)
        print("\nYou can now make requests without rate limit restrictions.")

    except redis.ConnectionError:
        print("\n❌ ERROR: Cannot connect to Redis")
        print("\nPossible solutions:")
        print("1. Make sure Redis container is running:")
        print("   docker compose ps redis")
        print("\n2. Start Redis if it's not running:")
        print("   docker compose up -d redis")
        print("\n3. Or just restart the web container:")
        print("   docker compose restart web")
        print("\n(In-memory rate limits are cleared on restart)")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nFallback: Restart the web container to clear in-memory limits:")
        print("  docker compose restart web")

if __name__ == "__main__":
    clear_rate_limits()
