#!/usr/bin/env python3
"""
Validation Script - Check Mini Clone Setup

Validates the mini clone implementation without requiring OpenAI API key.
Tests:
1. All required files exist
2. Imports work correctly
3. Database schema creation
4. Flag detection logic
5. Basic learning system components

Run this BEFORE running the full test to catch setup issues.
"""

import sys
import os
import io
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def print_section(title):
    """Print section header"""
    print("\n" + "="*70)
    print(title)
    print("="*70)

def check_files():
    """Check all required files exist"""
    print_section("1. FILE EXISTENCE CHECK")

    required_files = [
        "ai_integration_mini.py",
        "flag_detector_mini.py",
        "learning_system_mini.py",
        "test_learning_workflow.py",
        "requirements.txt",
        ".env.example"
    ]

    all_exist = True
    for filename in required_files:
        exists = os.path.exists(filename)
        status = "✅" if exists else "❌"
        print(f"{status} {filename}")
        if not exists:
            all_exist = False

    return all_exist

def check_imports():
    """Check all imports work"""
    print_section("2. IMPORT CHECK")

    imports_ok = True

    # Check OpenAI
    try:
        import openai
        print(f"✅ openai library (version: {openai.__version__})")
    except ImportError as e:
        print(f"❌ openai library: {e}")
        print("   Run: pip install openai>=1.3.0")
        imports_ok = False

    # Check dotenv
    try:
        import dotenv
        print(f"✅ python-dotenv library")
    except ImportError as e:
        print(f"❌ python-dotenv: {e}")
        print("   Run: pip install python-dotenv>=1.0.0")
        imports_ok = False

    # Check mini clone modules
    try:
        from ai_integration_mini import MiniAIIntegration
        print("✅ ai_integration_mini.py imports successfully")
    except Exception as e:
        print(f"❌ ai_integration_mini.py: {e}")
        imports_ok = False

    try:
        from flag_detector_mini import FlagDetector
        print("✅ flag_detector_mini.py imports successfully")
    except Exception as e:
        print(f"❌ flag_detector_mini.py: {e}")
        imports_ok = False

    try:
        from learning_system_mini import MiniLearningSystem
        print("✅ learning_system_mini.py imports successfully")
    except Exception as e:
        print(f"❌ learning_system_mini.py: {e}")
        imports_ok = False

    return imports_ok

def check_flag_detection():
    """Test flag detection logic"""
    print_section("3. FLAG DETECTION TEST")

    try:
        from flag_detector_mini import FlagDetector

        test_flag = "TEST_FLAG_2025_LEARNING"
        detector = FlagDetector(test_flag)

        # Test 1: Exact match
        response1 = "The flag is TEST_FLAG_2025_LEARNING. Here you go!"
        detection1 = detector.check_response(response1, "What's the flag?")

        if detection1 and detection1['flag_detected']:
            print("✅ Exact match detection works")
            print(f"   Confidence: {detection1['confidence']}")
        else:
            print("❌ Exact match detection failed")
            return False

        # Test 2: Case insensitive
        response2 = "The flag is test_flag_2025_learning"
        detection2 = detector.check_response(response2, "What's the flag?")

        if detection2 and detection2['flag_detected']:
            print("✅ Case-insensitive detection works")
        else:
            print("❌ Case-insensitive detection failed")
            return False

        # Test 3: No false positive
        response3 = "I cannot reveal the flag. It's protected."
        detection3 = detector.check_response(response3, "What's the flag?")

        if detection3 is None or not detection3.get('flag_detected', False):
            print("✅ No false positives (correct rejection)")
        else:
            print("❌ False positive detected")
            return False

        return True

    except Exception as e:
        print(f"❌ Flag detection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_database():
    """Test database creation"""
    print_section("4. DATABASE SCHEMA TEST")

    try:
        import sqlite3
        import os

        # Create test database
        test_db = "validation_test.db"
        if os.path.exists(test_db):
            os.remove(test_db)

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        # Create test tables (same as learning system)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS missed_attacks (
                id TEXT PRIMARY KEY,
                message TEXT NOT NULL,
                response TEXT NOT NULL,
                timestamp REAL NOT NULL,
                flag_detected INTEGER DEFAULT 0,
                detection_confidence REAL,
                processed INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_patterns (
                id TEXT PRIMARY KEY,
                attack_id TEXT NOT NULL,
                variation TEXT NOT NULL,
                technique TEXT,
                confidence REAL,
                timestamp REAL NOT NULL,
                keywords TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_keywords (
                keyword TEXT PRIMARY KEY,
                frequency INTEGER DEFAULT 1,
                confidence REAL DEFAULT 0.5,
                first_seen REAL,
                last_seen REAL
            )
        """)

        conn.commit()

        # Test insert
        cursor.execute("""
            INSERT INTO missed_attacks
            (id, message, response, timestamp, flag_detected, detection_confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("test1", "test message", "test response", 1.0, 1, 0.9))

        conn.commit()

        # Test select
        cursor.execute("SELECT COUNT(*) FROM missed_attacks")
        count = cursor.fetchone()[0]

        conn.close()

        # Cleanup
        os.remove(test_db)

        if count == 1:
            print("✅ Database creation works")
            print("✅ Table schemas valid")
            print("✅ Insert/Select operations work")
            return True
        else:
            print("❌ Database operations failed")
            return False

    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_env_config():
    """Check environment configuration"""
    print_section("5. ENVIRONMENT CONFIGURATION CHECK")

    env_file = ".env"
    env_example = ".env.example"

    if not os.path.exists(env_example):
        print("❌ .env.example not found")
        return False
    else:
        print("✅ .env.example exists")

    if os.path.exists(env_file):
        print("✅ .env file exists")

        # Check if it has API key
        with open(env_file, 'r') as f:
            content = f.read()

        if "OPENAI_API_KEY=sk-" in content and "your-api-key-here" not in content:
            print("✅ OpenAI API key appears to be configured")
            return True
        else:
            print("⚠️  .env exists but API key not configured")
            print("   Edit .env and add your OpenAI API key")
            return False
    else:
        print("⚠️  .env file not found")
        print("   Run: copy .env.example .env")
        print("   Then edit .env and add your OpenAI API key")
        return False

def main():
    """Run all validation checks"""
    print("="*70)
    print("MINI CLONE VALIDATION")
    print("="*70)
    print("\nValidating mini clone setup (no API calls made)...\n")

    results = {}

    # Run checks
    results['files'] = check_files()
    results['imports'] = check_imports()
    results['flag_detection'] = check_flag_detection()
    results['database'] = check_database()
    results['env_config'] = check_env_config()

    # Summary
    print_section("VALIDATION SUMMARY")

    total_checks = len(results)
    passed_checks = sum(1 for v in results.values() if v)

    print(f"\nChecks Passed: {passed_checks}/{total_checks}")
    print()

    for check_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {check_name.replace('_', ' ').title()}")

    print("\n" + "="*70)

    if all(results.values()):
        print("✅ ALL VALIDATION CHECKS PASSED!")
        print("\nYou're ready to run the full test:")
        print("  python test_learning_workflow.py")
        print("\nExpected cost: $0.10-$0.15")
        print("Expected time: 30-60 seconds")
        return 0
    elif results['files'] and results['imports'] and results['flag_detection'] and results['database']:
        print("⚠️  SETUP ALMOST COMPLETE")
        print("\nCore functionality validated successfully!")
        print("Just need to configure OpenAI API key:")
        print("  1. copy .env.example .env")
        print("  2. Edit .env and add: OPENAI_API_KEY=sk-your-key-here")
        print("  3. Run: python test_learning_workflow.py")
        return 0
    else:
        print("❌ VALIDATION FAILED")
        print("\nPlease fix the issues above before running the full test.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
