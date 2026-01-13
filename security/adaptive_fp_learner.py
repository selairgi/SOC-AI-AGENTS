#!/usr/bin/env python3
"""
Adaptive False Positive Learner

This module implements machine learning to automatically adjust Bayesian priors
and train lightweight models (Random Forest, XGBoost) based on real feedback.

Architecture:
1. Collect labeled data (confirmed FP vs real threats)
2. Update Bayesian priors empirically: P(FP | factor) = count_fp / total
3. Train ML model to predict P(FP) directly from features
4. Compare Bayesian vs ML approaches
"""

import logging
import pickle
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, Counter
import json
import numpy as np

# Try to import scikit-learn for ML models
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    SKLEARN_AVAILABLE = True
    print("scikit-learn successfully loaded.")
except ImportError as e:
    SKLEARN_AVAILABLE = False
    print(f"Warning: scikit-learn not installed. ML training disabled. Error: {e}")
except Exception as e:
    SKLEARN_AVAILABLE = False
    print(f"Warning: Error loading scikit-learn: {e}")

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert


@dataclass
class LabeledSample:
    """A labeled sample for training"""
    alert_id: str
    timestamp: float
    message: str

    # Features extracted from the detection system
    features: Dict[str, float]

    # Ground truth label
    is_false_positive: bool  # True = FP, False = Real threat

    # Metadata
    threat_type: str
    severity: str
    user_id: Optional[str] = None

    # Who labeled it
    labeled_by: str = "auto"  # "auto", "analyst", "user_feedback"
    confidence: float = 1.0   # Confidence in the label (0-1)


class AdaptiveFPLearner:
    """
    Adaptive false positive learner using both:
    1. Empirical Bayesian prior updates
    2. ML model training (Random Forest / XGBoost)
    """

    def __init__(self, cache_dir: str = "security/.cache"):
        self.logger = logging.getLogger("AdaptiveFPLearner")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        # Labeled samples collected over time
        self.labeled_samples: List[LabeledSample] = []

        # Empirical statistics for Bayesian prior updates
        # Format: {"factor_name": {"fp_count": N, "tp_count": M}}
        self.empirical_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"fp_count": 0, "tp_count": 0}
        )

        # Trained ML models
        self.ml_model = None
        self.feature_names: Optional[List[str]] = None
        self.model_metadata: Dict[str, Any] = {}

        # Load existing data if available
        self._load_training_data()

    def _load_training_data(self):
        """Load previously collected training data"""
        samples_file = self.cache_dir / "labeled_samples.pkl"
        stats_file = self.cache_dir / "empirical_stats.json"
        model_file = self.cache_dir / "fp_ml_model.pkl"

        # Load labeled samples
        if samples_file.exists():
            try:
                with open(samples_file, 'rb') as f:
                    self.labeled_samples = pickle.load(f)
                self.logger.info(f"Loaded {len(self.labeled_samples)} labeled samples")
            except Exception as e:
                self.logger.warning(f"Failed to load labeled samples: {e}")

        # Load empirical stats
        if stats_file.exists():
            try:
                with open(stats_file, 'r') as f:
                    self.empirical_stats = json.load(f)
                self.logger.info(f"Loaded empirical stats for {len(self.empirical_stats)} factors")
            except Exception as e:
                self.logger.warning(f"Failed to load empirical stats: {e}")

        # Load ML model
        if model_file.exists() and SKLEARN_AVAILABLE:
            try:
                with open(model_file, 'rb') as f:
                    model_data = pickle.load(f)
                    self.ml_model = model_data['model']
                    self.feature_names = model_data['feature_names']
                    self.model_metadata = model_data['metadata']
                self.logger.info(f"Loaded ML model: {self.model_metadata.get('model_type', 'unknown')}")
            except Exception as e:
                self.logger.warning(f"Failed to load ML model: {e}")

    def add_labeled_sample(
        self,
        alert: Alert,
        message: str,
        features: Dict[str, float],
        is_false_positive: bool,
        labeled_by: str = "auto",
        confidence: float = 1.0
    ):
        """
        Add a labeled sample to the training dataset.

        Args:
            alert: The alert that was analyzed
            message: The message text
            features: Dictionary of features extracted (e.g., {"educational_indicator": 0.90, ...})
            is_false_positive: True if confirmed FP, False if real threat
            labeled_by: Who provided the label ("auto", "analyst", "user_feedback")
            confidence: Confidence in the label (0.0-1.0)
        """
        sample = LabeledSample(
            alert_id=alert.id,
            timestamp=time.time(),
            message=message,
            features=features,
            is_false_positive=is_false_positive,
            threat_type=alert.threat_type.value,
            severity=alert.severity,
            labeled_by=labeled_by,
            confidence=confidence
        )

        self.labeled_samples.append(sample)

        # Update empirical statistics
        for factor_name, factor_value in features.items():
            # Only update if the factor was present (non-zero)
            if factor_value > 0:
                if is_false_positive:
                    self.empirical_stats[factor_name]["fp_count"] += 1
                else:
                    self.empirical_stats[factor_name]["tp_count"] += 1

        self.logger.info(
            f"Added labeled sample: {alert.id} | "
            f"FP={is_false_positive} | "
            f"by={labeled_by} | "
            f"confidence={confidence:.2f}"
        )

        # Save incrementally
        if len(self.labeled_samples) % 10 == 0:
            self._save_training_data()

    def _save_training_data(self):
        """Save training data to disk"""
        samples_file = self.cache_dir / "labeled_samples.pkl"
        stats_file = self.cache_dir / "empirical_stats.json"

        # Save labeled samples
        try:
            with open(samples_file, 'wb') as f:
                pickle.dump(self.labeled_samples, f)
        except Exception as e:
            self.logger.error(f"Failed to save labeled samples: {e}")

        # Save empirical stats
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.empirical_stats, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save empirical stats: {e}")

    def get_updated_bayesian_priors(self, smoothing: float = 1.0) -> Dict[str, float]:
        """
        Compute updated Bayesian priors based on empirical data.

        Uses Laplace smoothing to avoid overfitting on small samples:
        P(FP | factor) = (fp_count + smoothing) / (fp_count + tp_count + 2*smoothing)

        Args:
            smoothing: Laplace smoothing parameter (default: 1.0)

        Returns:
            Dictionary of factor_name -> P(FP | factor)
        """
        updated_priors = {}

        for factor_name, stats in self.empirical_stats.items():
            fp_count = stats["fp_count"]
            tp_count = stats["tp_count"]
            total = fp_count + tp_count

            if total == 0:
                # No data for this factor, skip
                continue

            # Laplace smoothing
            prior = (fp_count + smoothing) / (total + 2 * smoothing)
            updated_priors[factor_name] = prior

            self.logger.debug(
                f"Updated prior: {factor_name} = {prior:.3f} "
                f"(FP={fp_count}, TP={tp_count})"
            )

        return updated_priors

    def train_ml_model(
        self,
        model_type: str = "random_forest",
        min_samples: int = 50,
        test_size: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train an ML model to predict P(FP) from features.

        Args:
            model_type: "random_forest" or "gradient_boosting"
            min_samples: Minimum samples required for training
            test_size: Fraction of data to use for testing

        Returns:
            Dictionary with training results and metrics
        """
        if not SKLEARN_AVAILABLE:
            self.logger.error("scikit-learn not available. Cannot train ML model.")
            return {"error": "scikit-learn not installed"}

        if len(self.labeled_samples) < min_samples:
            self.logger.warning(
                f"Not enough labeled samples for training: "
                f"{len(self.labeled_samples)} < {min_samples}"
            )
            return {"error": f"Need at least {min_samples} samples"}

        # Prepare training data
        X, y, feature_names = self._prepare_training_data()

        if len(X) == 0:
            return {"error": "No valid training data"}

        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Train model
        if model_type == "random_forest":
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                random_state=42,
                class_weight="balanced"  # Handle imbalanced data
            )
        elif model_type == "gradient_boosting":
            model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        else:
            return {"error": f"Unknown model type: {model_type}"}

        self.logger.info(f"Training {model_type} on {len(X_train)} samples...")
        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]  # P(FP)

        # Metrics
        accuracy = (y_pred == y_test).mean()
        auc = roc_auc_score(y_test, y_pred_proba)

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        # Feature importance
        if hasattr(model, 'feature_importances_'):
            feature_importance = dict(zip(feature_names, model.feature_importances_))
            # Sort by importance
            feature_importance = dict(
                sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
            )
        else:
            feature_importance = {}

        # Save model
        self.ml_model = model
        self.feature_names = feature_names
        self.model_metadata = {
            "model_type": model_type,
            "trained_at": time.time(),
            "n_samples": len(X),
            "n_features": len(feature_names),
            "accuracy": accuracy,
            "auc": auc,
            "feature_importance": feature_importance
        }

        model_file = self.cache_dir / "fp_ml_model.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump({
                'model': model,
                'feature_names': feature_names,
                'metadata': self.model_metadata
            }, f)

        self.logger.info(
            f"Model trained successfully: "
            f"Accuracy={accuracy:.3f}, AUC={auc:.3f}"
        )

        return {
            "model_type": model_type,
            "n_samples": len(X),
            "n_train": len(X_train),
            "n_test": len(X_test),
            "accuracy": accuracy,
            "auc": auc,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            },
            "feature_importance": feature_importance
        }

    def _prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare training data from labeled samples.

        Returns:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) - 1 for FP, 0 for real threat
            feature_names: List of feature names
        """
        # Collect all unique features
        all_features = set()
        for sample in self.labeled_samples:
            all_features.update(sample.features.keys())

        feature_names = sorted(list(all_features))

        # Build feature matrix
        X = []
        y = []

        for sample in self.labeled_samples:
            # Create feature vector
            feature_vector = []
            for feature_name in feature_names:
                feature_vector.append(sample.features.get(feature_name, 0.0))

            X.append(feature_vector)
            y.append(1 if sample.is_false_positive else 0)

        return np.array(X), np.array(y), feature_names

    def predict_fp_probability_ml(self, features: Dict[str, float]) -> Optional[float]:
        """
        Predict P(FP) using the trained ML model.

        Args:
            features: Dictionary of features

        Returns:
            P(FP) probability (0.0-1.0) or None if model not available
        """
        if self.ml_model is None or self.feature_names is None:
            return None

        # Build feature vector
        feature_vector = []
        for feature_name in self.feature_names:
            feature_vector.append(features.get(feature_name, 0.0))

        # Predict
        X = np.array([feature_vector])
        proba = self.ml_model.predict_proba(X)[0, 1]  # P(FP)

        return float(proba)

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the learner"""
        total_samples = len(self.labeled_samples)
        fp_samples = sum(1 for s in self.labeled_samples if s.is_false_positive)
        tp_samples = total_samples - fp_samples

        return {
            "total_samples": total_samples,
            "fp_samples": fp_samples,
            "tp_samples": tp_samples,
            "fp_rate": fp_samples / total_samples if total_samples > 0 else 0,
            "n_factors_tracked": len(self.empirical_stats),
            "ml_model_available": self.ml_model is not None,
            "ml_model_metadata": self.model_metadata if self.ml_model else None
        }
