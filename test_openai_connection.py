#!/usr/bin/env python3
"""Test OpenAI API Connection"""

import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

print("=" * 60)
print("Testing OpenAI API Connection")
print("=" * 60)
print(f"\nAPI Key: {api_key[:20]}...{api_key[-10:] if api_key else 'NOT SET'}")

try:
    from openai import OpenAI

    client = OpenAI(
        api_key=api_key,
        timeout=30.0,
        max_retries=1
    )

    print("\n[1/3] OpenAI client initialized...")

    # Test with a simple request
    print("[2/3] Testing API connection...")

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": "Say 'API works!'"}
        ],
        max_tokens=10
    )

    print("[3/3] API Response received!")
    print(f"\nResponse: {response.choices[0].message.content}")
    print(f"Tokens used: {response.usage.total_tokens}")

    print("\n" + "=" * 60)
    print("SUCCESS: OpenAI API is working correctly!")
    print("=" * 60)

except Exception as e:
    error_msg = str(e)
    print("\n" + "=" * 60)
    print("ERROR: OpenAI API connection failed!")
    print("=" * 60)
    print(f"\nError: {error_msg}")

    # Provide specific guidance
    if "authentication" in error_msg.lower() or "api key" in error_msg.lower():
        print("\nPOSSIBLE CAUSE: Invalid or expired API key")
        print("SOLUTION:")
        print("1. Go to https://platform.openai.com/api-keys")
        print("2. Generate a new API key")
        print("3. Update your .env file with: OPENAI_API_KEY=sk-...")
        print("4. Restart Docker: docker compose restart web")

    elif "quota" in error_msg.lower() or "rate limit" in error_msg.lower():
        print("\nPOSSIBLE CAUSE: API quota exceeded or rate limit")
        print("SOLUTION:")
        print("1. Check your usage at https://platform.openai.com/usage")
        print("2. Add credits at https://platform.openai.com/account/billing")
        print("3. Wait a few minutes if rate limited")

    elif "connection" in error_msg.lower() or "timeout" in error_msg.lower():
        print("\nPOSSIBLE CAUSE: Network connection issue")
        print("SOLUTION:")
        print("1. Check your internet connection")
        print("2. Check if a firewall is blocking OpenAI API")
        print("3. Try again in a few minutes")
        print("4. Check OpenAI status: https://status.openai.com/")

    print("\n" + "=" * 60)
