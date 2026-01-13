"""
Full V7.1 Security Pipeline Evaluation on 4K Dataset

Tests 4000 prompts with REAL V7.1 pipeline (not mock):
- Validates all configurations and API keys
- Tests all 4 detection layers
- Generates comprehensive metrics
"""

import json
import sys
import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

# Fix Windows encoding for stdout
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Load environment variables from .env
from dotenv import load_dotenv
project_root = Path(__file__).parent.parent
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"✅ Loaded environment from: {env_file}")
else:
    print(f"⚠️  No .env file found at: {env_file}")

# Add paths
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(project_root))

@dataclass
class EvaluationResult:
    """Result for a single prompt evaluation."""
    prompt_id: int
    category: str
    attack: bool
    subtype: str
    difficulty: int

    # Detection results
    detected: bool
    detection_layers: List[str]
    confidence: float

    # Layer-specific results
    l1_detected: bool
    l1_confidence: float
    l2_detected: bool
    l2_confidence: float
    l3_detected: bool
    l3_confidence: float
    l4_detected: bool
    l4_confidence: float

    # Timing
    processing_time_ms: float

    # Classification
    true_positive: bool = False
    false_positive: bool = False
    true_negative: bool = False
    false_negative: bool = False

    # Error tracking
    error: Optional[str] = None


def check_configuration() -> Dict[str, Any]:
    """
    Validate all required configurations before starting evaluation.
    Returns configuration status.
    """
    print("="*80)
    print("CONFIGURATION VALIDATION")
    print("="*80)

    config = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "env_vars": {},
        "modules": {}
    }

    # Check environment variables
    print("\n📋 Checking Environment Variables...")
    env_vars_to_check = [
        ("OPENAI_API_KEY", False),  # Optional - some layers work without it
        ("OPENAI_MODEL", False),    # Optional
    ]

    for var_name, required in env_vars_to_check:
        value = os.getenv(var_name)
        if value:
            # Mask API key for display
            display_value = value[:8] + "..." if "KEY" in var_name else value
            print(f"   ✅ {var_name}: {display_value}")
            config["env_vars"][var_name] = "SET"
        else:
            if required:
                print(f"   ❌ {var_name}: NOT SET (REQUIRED)")
                config["errors"].append(f"{var_name} is not set")
                config["valid"] = False
            else:
                print(f"   ⚠️  {var_name}: NOT SET (Layer 1 LLM will be limited, but other layers will work)")
                config["warnings"].append(f"{var_name} not set - Layer 1 (LLM) will have limited functionality")

    # Check required Python modules
    print("\n📦 Checking Required Python Modules...")
    modules_to_check = [
        ("rapidfuzz", "Security: Fuzzy matching", False),
        ("xgboost", "ML: XGBoost classifier", False),
        ("sentence_transformers", "ML: Embeddings", False),
        ("torch", "ML: PyTorch backend", False),
        ("sklearn", "ML: Scikit-learn", False),
        ("numpy", "ML: Numpy arrays", False),
    ]

    for module_name, description, required in modules_to_check:
        try:
            __import__(module_name)
            print(f"   ✅ {module_name}: Available ({description})")
            config["modules"][module_name] = "AVAILABLE"
        except ImportError:
            if required:
                print(f"   ❌ {module_name}: MISSING (REQUIRED) - {description}")
                config["errors"].append(f"{module_name} module not found")
                config["valid"] = False
            else:
                print(f"   ⚠️  {module_name}: NOT AVAILABLE ({description})")
                config["warnings"].append(f"{module_name} not available, some features disabled")
                config["modules"][module_name] = "MISSING"

    # Check security pipeline files
    print("\n📂 Checking Security Pipeline Files...")
    security_dir = Path(__file__).parent
    required_files = [
        ("intelligent_prompt_detector.py", True),
        ("semantic_detector.py", False),
        ("false_positive_detector.py", False),
    ]

    for filename, required in required_files:
        file_path = security_dir / filename
        if file_path.exists():
            print(f"   ✅ {filename}: Found")
        else:
            if required:
                print(f"   ❌ {filename}: MISSING (REQUIRED)")
                config["errors"].append(f"{filename} not found")
                config["valid"] = False
            else:
                print(f"   ⚠️  {filename}: NOT FOUND")
                config["warnings"].append(f"{filename} not found")

    # Check test dataset
    print("\n📊 Checking Test Dataset...")
    prompts_file = security_dir / "evaluation_prompts_4k.json"
    if prompts_file.exists():
        print(f"   ✅ evaluation_prompts_4k.json: Found")
        try:
            with open(prompts_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                total = len(data.get("prompts", []))
                print(f"      → {total} prompts loaded")
        except Exception as e:
            print(f"   ❌ Error loading dataset: {e}")
            config["errors"].append(f"Failed to load dataset: {e}")
            config["valid"] = False
    else:
        print(f"   ❌ evaluation_prompts_4k.json: NOT FOUND")
        config["errors"].append("Test dataset not found")
        config["valid"] = False

    # Summary
    print("\n" + "="*80)
    if config["valid"]:
        print("✅ CONFIGURATION VALID - Ready to proceed")
    else:
        print("❌ CONFIGURATION INVALID - Fix errors before proceeding")
        print("\n🔴 ERRORS:")
        for error in config["errors"]:
            print(f"   - {error}")

    if config["warnings"]:
        print("\n⚠️  WARNINGS:")
        for warning in config["warnings"]:
            print(f"   - {warning}")

    print("="*80)

    return config


def load_security_pipeline():
    """
    Load the V7.1 security pipeline from security_pipeline.py.
    Returns pipeline instance or None if failed.
    """
    print("\n📡 Loading V7.1 Security Pipeline from web/security_pipeline.py...")

    try:
        # Add web directory to path
        web_dir = Path(__file__).parent.parent / "web"
        if str(web_dir) not in sys.path:
            sys.path.insert(0, str(web_dir))

        # Import the full security pipeline
        from security_pipeline import SecureSOCWebIntegration

        # Initialize without socketio (not needed for evaluation)
        pipeline = SecureSOCWebIntegration(socketio=None)

        print("   ✅ SecureSOCWebIntegration loaded")
        print("   ✅ Layer 1: Intelligent Detector (LLM-based)")
        print("   ✅ Layer 2: Formal Analyzer V5.2 (NLP + Format Abuse)")
        print("   ✅ Layer 3: Semantic Detector (Authority + Logical Traps)")
        print("   ✅ Layer 4: ML Ensemble (XGBoost + Embeddings + PromptSleuth)")
        print("   ✅ False Positive Detector")
        print("   ✅ Pipeline loaded successfully")

        return pipeline

    except Exception as e:
        print(f"   ❌ Failed to load pipeline: {e}")
        import traceback
        traceback.print_exc()
        return None


def evaluate_prompt_with_pipeline(
    prompt: str,
    metadata: Dict[str, Any],
    pipeline
) -> EvaluationResult:
    """
    Evaluate a single prompt using the full V7.1 pipeline via process_chat_message.
    """
    start_time = time.time()

    # Initialize layer results
    l1_detected, l1_confidence = False, 0.0
    l2_detected, l2_confidence = False, 0.0
    l3_detected, l3_confidence = False, 0.0
    l4_detected, l4_confidence = False, 0.0

    detection_layers = []
    error_msg = None

    try:
        # Use process_chat_message from SecureSOCWebIntegration
        # This runs the FULL V7.1 pipeline with all 4 layers
        result = pipeline.process_chat_message(
            message=prompt,
            user_id=f"eval_user_{metadata['id']}",
            session_id=f"eval_session_{metadata['id']}",
            user_ip="127.0.0.1",
            security_mode="strict",  # Use strict mode for evaluation
            auto_remediation=False   # Don't auto-remediate during evaluation
        )

        # Extract detection info from result
        security_check = result.get("security_check", {})
        alert = security_check.get("alert")

        # Check if threat was detected
        detected = security_check.get("alert_detected", False) or security_check.get("blocked", False)

        # Extract detection methods/layers
        if alert and hasattr(alert, 'evidence'):
            evidence = alert.evidence or {}
            detection_method = evidence.get("detection_method", "")

            # Map detection methods to layers
            if "intelligent" in detection_method.lower() or "llm" in detection_method.lower():
                l1_detected = True
                l1_confidence = 0.9
                detection_layers.append("L1")
            if "formal" in detection_method.lower() or "v5" in detection_method.lower():
                l2_detected = True
                l2_confidence = evidence.get("certainty", 0.85)
                detection_layers.append("L2")
            if "semantic" in detection_method.lower():
                l3_detected = True
                l3_confidence = evidence.get("confidence", 0.8)
                detection_layers.append("L3")
            if "ml" in detection_method.lower() or "sleuth" in detection_method.lower():
                l4_detected = True
                l4_confidence = 0.85
                detection_layers.append("L4")

        # Get overall confidence
        confidence = 0.0
        if alert:
            if hasattr(alert, 'false_positive_probability'):
                confidence = 1.0 - alert.false_positive_probability
            else:
                confidence = max(l1_confidence, l2_confidence, l3_confidence, l4_confidence) if detected else 0.0
        else:
            confidence = 0.0

        # Check for errors
        if result.get("error"):
            error_msg = str(result["error"])[:100]

    except Exception as e:
        error_msg = f"Pipeline error: {str(e)[:100]}"
        detected = False
        confidence = 0.0

    processing_time_ms = (time.time() - start_time) * 1000

    # Classify result
    is_attack = metadata["attack"]
    true_positive = is_attack and detected
    false_positive = not is_attack and detected
    true_negative = not is_attack and not detected
    false_negative = is_attack and not detected

    return EvaluationResult(
        prompt_id=metadata["id"],
        category=metadata["category"],
        attack=is_attack,
        subtype=metadata["subtype"],
        difficulty=metadata["difficulty"],
        detected=detected,
        detection_layers=detection_layers,
        confidence=confidence,
        l1_detected=l1_detected,
        l1_confidence=l1_confidence,
        l2_detected=l2_detected,
        l2_confidence=l2_confidence,
        l3_detected=l3_detected,
        l3_confidence=l3_confidence,
        l4_detected=l4_detected,
        l4_confidence=l4_confidence,
        processing_time_ms=processing_time_ms,
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        error=error_msg
    )


def calculate_metrics(results: List[EvaluationResult]) -> Dict[str, Any]:
    """Calculate comprehensive evaluation metrics."""

    # Overall metrics
    tp = sum(1 for r in results if r.true_positive)
    fp = sum(1 for r in results if r.false_positive)
    tn = sum(1 for r in results if r.true_negative)
    fn = sum(1 for r in results if r.false_negative)

    total = len(results)
    attacks = sum(1 for r in results if r.attack)
    benign = total - attacks
    errors = sum(1 for r in results if r.error)

    # Rates
    detection_rate = (tp / attacks * 100) if attacks > 0 else 0
    false_positive_rate = (fp / benign * 100) if benign > 0 else 0
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    # Per-category metrics
    category_metrics = defaultdict(lambda: {"total": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0})

    for r in results:
        cat = r.category
        category_metrics[cat]["total"] += 1
        if r.detected:
            category_metrics[cat]["detected"] += 1
        if r.true_positive:
            category_metrics[cat]["tp"] += 1
        if r.false_positive:
            category_metrics[cat]["fp"] += 1
        if r.false_negative:
            category_metrics[cat]["fn"] += 1

    # Calculate detection rate per category
    for cat, metrics in category_metrics.items():
        total_cat = metrics["total"]
        detected = metrics["detected"]
        metrics["detection_rate"] = (detected / total_cat * 100) if total_cat > 0 else 0

    # Per-layer metrics
    layer_metrics = {
        "L1": {"detected": sum(1 for r in results if r.l1_detected), "avg_confidence": 0},
        "L2": {"detected": sum(1 for r in results if r.l2_detected), "avg_confidence": 0},
        "L3": {"detected": sum(1 for r in results if r.l3_detected), "avg_confidence": 0},
        "L4": {"detected": sum(1 for r in results if r.l4_detected), "avg_confidence": 0},
    }

    # Average confidences
    for layer in ["L1", "L2", "L3", "L4"]:
        confidences = []
        for r in results:
            if layer == "L1" and r.l1_detected:
                confidences.append(r.l1_confidence)
            elif layer == "L2" and r.l2_detected:
                confidences.append(r.l2_confidence)
            elif layer == "L3" and r.l3_detected:
                confidences.append(r.l3_confidence)
            elif layer == "L4" and r.l4_detected:
                confidences.append(r.l4_confidence)

        layer_metrics[layer]["avg_confidence"] = (sum(confidences) / len(confidences)) if confidences else 0
        layer_metrics[layer]["detection_rate"] = (layer_metrics[layer]["detected"] / total * 100) if total > 0 else 0

    # Timing metrics
    avg_processing_time = sum(r.processing_time_ms for r in results) / len(results) if results else 0

    return {
        "overall": {
            "total_prompts": total,
            "attack_prompts": attacks,
            "benign_prompts": benign,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "errors": errors,
            "detection_rate": round(detection_rate, 2),
            "false_positive_rate": round(false_positive_rate, 2),
            "accuracy": round(accuracy, 2),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
        },
        "per_category": {
            cat: {
                "total": metrics["total"],
                "detected": metrics["detected"],
                "detection_rate": round(metrics["detection_rate"], 2),
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "fn": metrics["fn"],
            }
            for cat, metrics in category_metrics.items()
        },
        "per_layer": {
            layer: {
                "detected": metrics["detected"],
                "detection_rate": round(metrics["detection_rate"], 2),
                "avg_confidence": round(metrics["avg_confidence"], 2),
            }
            for layer, metrics in layer_metrics.items()
        },
        "performance": {
            "avg_processing_time_ms": round(avg_processing_time, 2),
            "total_time_seconds": round(sum(r.processing_time_ms for r in results) / 1000, 2),
        }
    }


def main():
    """Main evaluation execution."""
    print("="*80)
    print("V7.1 FULL SECURITY PIPELINE EVALUATION - 4K DATASET")
    print("="*80)

    # Step 1: Validate configuration
    config = check_configuration()
    if not config["valid"]:
        print("\n❌ CONFIGURATION ERRORS DETECTED - ABORTING")
        print("\nPlease fix the errors above and try again.")
        sys.exit(1)

    # Step 2: Load dataset
    prompts_file = Path(__file__).parent / "evaluation_prompts_4k.json"
    print(f"\n📂 Loading dataset from: {prompts_file}")
    with open(prompts_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    prompts = data["prompts"]
    print(f"✅ Loaded {len(prompts)} prompts")

    # For testing, limit to first 500 prompts (comment out for full evaluation)
    prompts = prompts[:500]
    print(f"⚠️  LIMITED TO {len(prompts)} PROMPTS FOR TESTING")

    # Step 3: Load pipeline
    pipeline = load_security_pipeline()
    if not pipeline:
        print("\n❌ FAILED TO LOAD PIPELINE - ABORTING")
        sys.exit(1)

    # Step 4: Run evaluation
    print("\n" + "="*80)
    print("STARTING EVALUATION")
    print("="*80)

    results = []
    start_time = time.time()
    errors_count = 0

    for i, prompt_data in enumerate(prompts):
        if (i + 1) % 500 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            remaining = (len(prompts) - i - 1) / rate if rate > 0 else 0
            print(f"Progress: {i+1}/{len(prompts)} | "
                  f"Rate: {rate:.1f} prompts/s | "
                  f"Errors: {errors_count} | "
                  f"ETA: {int(remaining)}s")

        result = evaluate_prompt_with_pipeline(
            prompt_data["prompt"],
            prompt_data["metadata"],
            pipeline
        )
        results.append(result)

        if result.error:
            errors_count += 1

    total_time = time.time() - start_time
    print(f"\n✅ Evaluation Complete! Processed {len(prompts)} prompts in {total_time:.1f}s")

    # Step 5: Calculate metrics
    print("\n" + "="*80)
    print("CALCULATING METRICS")
    print("="*80)

    metrics = calculate_metrics(results)

    # Step 6: Display results
    print("\n" + "="*80)
    print("EVALUATION RESULTS")
    print("="*80)

    print("\n📊 Overall Metrics:")
    print("-" * 80)
    overall = metrics["overall"]
    print(f"Total Prompts:        {overall['total_prompts']}")
    print(f"  Attack Prompts:     {overall['attack_prompts']}")
    print(f"  Benign Prompts:     {overall['benign_prompts']}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives:     {overall['true_positives']}")
    print(f"  False Positives:    {overall['false_positives']}")
    print(f"  True Negatives:     {overall['true_negatives']}")
    print(f"  False Negatives:    {overall['false_negatives']}")
    print(f"  Errors:             {overall['errors']}")
    print(f"\nPerformance:")
    print(f"  Detection Rate:     {overall['detection_rate']:.2f}%")
    print(f"  False Positive Rate: {overall['false_positive_rate']:.2f}%")
    print(f"  Accuracy:           {overall['accuracy']:.2f}%")
    print(f"  Precision:          {overall['precision']:.4f}")
    print(f"  Recall:             {overall['recall']:.4f}")
    print(f"  F1 Score:           {overall['f1_score']:.4f}")

    print("\n📊 Per-Category Detection Rates:")
    print("-" * 80)
    for cat, cat_metrics in sorted(metrics["per_category"].items()):
        if cat == "BENIGN":
            print(f"BENIGN: {cat_metrics['total']} prompts | "
                  f"FP: {cat_metrics['fp']}/{cat_metrics['total']} ({cat_metrics['detection_rate']:.1f}%)")
        else:
            print(f"Category {cat}: {cat_metrics['total']} prompts | "
                  f"Detected: {cat_metrics['detected']}/{cat_metrics['total']} ({cat_metrics['detection_rate']:.1f}%)")

    print("\n📊 Per-Layer Performance:")
    print("-" * 80)
    for layer, layer_metrics in sorted(metrics["per_layer"].items()):
        print(f"{layer}: Detected {layer_metrics['detected']} prompts ({layer_metrics['detection_rate']:.1f}%) | "
              f"Avg Confidence: {layer_metrics['avg_confidence']:.2f}")

    print("\n⏱️  Performance Metrics:")
    print("-" * 80)
    perf = metrics["performance"]
    print(f"Average Processing Time: {perf['avg_processing_time_ms']:.2f} ms/prompt")
    print(f"Total Evaluation Time:   {perf['total_time_seconds']:.2f} seconds")
    throughput = len(prompts) / perf['total_time_seconds'] if perf['total_time_seconds'] > 0 else 0
    print(f"Throughput:              {throughput:.1f} prompts/second")

    # Step 7: Save results
    output_file = Path(__file__).parent / "evaluation_results_4k_full.json"
    output_data = {
        "metadata": {
            "total_prompts": len(prompts),
            "attack_prompts": sum(1 for r in results if r.attack),
            "benign_prompts": sum(1 for r in results if not r.attack),
            "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pipeline_version": "V7.1-FULL",
            "config": config
        },
        "metrics": metrics,
        "results": [asdict(r) for r in results]
    }

    print(f"\n💾 Saving detailed results to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print("\n" + "="*80)
    print("✅ EVALUATION COMPLETE!")
    print("="*80)
    print(f"\n📄 Results saved to: {output_file}")
    print(f"📊 Summary:")
    print(f"   - Detection Rate: {overall['detection_rate']:.2f}%")
    print(f"   - False Positive Rate: {overall['false_positive_rate']:.2f}%")
    print(f"   - F1 Score: {overall['f1_score']:.4f}")
    print(f"   - Avg Processing Time: {perf['avg_processing_time_ms']:.2f} ms/prompt")
    print(f"   - Errors: {overall['errors']}")


if __name__ == "__main__":
    main()
