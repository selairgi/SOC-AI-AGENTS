# Comprehensive Test Runner

## Overview

The `run_all_tests.py` file is a comprehensive test suite that runs all tests for the SOC AI agents system and saves detailed results to a file.

## What It Tests

### 1. Prompt Injection Tests
- **Direct Override**: Tests for attempts to override system instructions
- **Role Manipulation**: Tests for attempts to manipulate AI roles
- **Code Injection**: Tests for code execution attempts
- **System Prompt Extraction**: Tests for attempts to extract system prompts

### 2. Workflow Tests
Tests the complete intelligence chain:
- **Builder (Detection)**: Detects threats from log entries
- **Analyst (Planning)**: Makes intelligent remediation decisions
- **Remediator (Execution)**: Executes remediation actions safely

### 3. Test Scenarios
- Localhost safety checks (should prevent blocking)
- False positive detection (should downgrade benign requests)
- Critical external attacks (should block)
- Code injection attacks
- Low confidence ambiguity (should investigate, not block)
- Normal queries (should not trigger)

## Usage

### Run All Tests
```bash
python tests/run_all_tests.py
```

### Custom Output File
You can modify the output file name in the script or change it programmatically:
```python
runner = ComprehensiveTestRunner(output_file="my_results.txt")
```

## Output

The test runner creates a file (default: `comprehensive_test_results.txt`) containing:

1. **Detailed Test Results**: Each test case with pass/fail status
2. **Category Breakdown**: Accuracy metrics per category
3. **Workflow Results**: Intelligence chain performance
4. **Memory Statistics**: Patterns learned and stored
5. **Overall Summary**: Total tests, detection rates, execution time

## Metrics Tracked

### Prompt Injection Metrics
- Total tests
- Detection rate
- Missed detections
- False positives
- Average certainty scores
- Category-specific accuracy

### Workflow Metrics
- Total scenarios
- Detection rate
- Correct planning decisions
- Correct execution decisions
- Safety interventions (localhost protection)
- False positives caught

### Memory Metrics
- Total patterns stored
- Total detections
- Total alert decisions

## Example Output Structure

```
====================================================================================================
COMPREHENSIVE SOC AGENTS TEST SUITE
Started at: 2024-01-15 10:30:00
====================================================================================================

[Prompt Injection Tests...]

[Workflow Tests...]

====================================================================================================
COMPREHENSIVE TEST SUMMARY
====================================================================================================

PROMPT INJECTION TESTS:
  Total Tests: 40
  Detected: 36
  Missed: 4
  Overall Accuracy: 90.00%
  Average Certainty: 0.48
  Detection Rate: 90.00%

WORKFLOW TESTS:
  Total Scenarios: 6
  Detections: 5/6 (83.3%)
  Correct Plans: 5/5 (100.0%)
  Correct Executions: 5/5 (100.0%)
  Safety Interventions: 1
  False Positives Caught: 1

MEMORY STATISTICS:
  Total Patterns Stored: 45
  Total Detections: 120
  Total Alert Decisions: 85

OVERALL STATISTICS:
  Total Tests Run: 46
  Total Detections: 41
  Overall Detection Rate: 89.13%
  Test Execution Time: 12.34 seconds
```

## Features

- **Automatic Fine-tuning**: Learns from missed patterns
- **Comprehensive Metrics**: Tracks accuracy, certainty, and performance
- **File Output**: All results saved to a text file for analysis
- **Console Output**: Real-time progress updates
- **Error Handling**: Graceful error handling with detailed tracebacks

## Integration

This test runner can be integrated into:
- CI/CD pipelines
- Automated testing workflows
- Performance monitoring
- Accuracy tracking over time

## Notes

- Tests run asynchronously for better performance
- Results are saved incrementally (file is flushed after each test)
- Memory database is created for pattern storage
- All tests use realistic log entry structures

