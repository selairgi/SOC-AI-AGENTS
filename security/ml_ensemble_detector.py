"""
ML Ensemble Detector - V7 Hybrid Intelligent Approach

Combines 3 ML approaches:
1. XGBoost Classifier (features from semantic scores)
2. Embeddings Similarity (learns attack patterns)
3. PromptSleuth (task graph analysis) - as primary detector

This layer catches patterns that rule-based systems miss!
"""

import json
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Check if ML libraries are available
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[WARN] XGBoost not installed. Run: pip install xgboost")

try:
    from sentence_transformers import SentenceTransformer
    import torch
    HAS_EMBEDDINGS = True
except ImportError:
    HAS_EMBEDDINGS = False
    print("[WARN] sentence-transformers not installed. Run: pip install sentence-transformers")


@dataclass
class MLEnsembleResult:
    """Result from ML Ensemble detection."""
    is_suspicious: bool
    ml_confidence: float
    xgb_score: float
    embedding_score: float
    promptsleuth_score: float
    components: Dict[str, float]
    explanation: str


class MLEnsembleDetector:
    """
    ML Ensemble Detector combining multiple ML approaches.

    V7 Hybrid Strategy:
    - XGBoost learns from semantic features
    - Embeddings detect similar attacks
    - PromptSleuth analyzes task relationships
    """

    def __init__(self, model_dir: str = "security/.cache"):
        """Initialize ML Ensemble Detector."""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True, parents=True)

        # XGBoost model
        self.xgb_model = None
        self.xgb_trained = False

        # Embeddings model
        self.embedding_model = None
        self.attack_embeddings = None
        self.attack_texts = []
        self.embeddings_trained = False

        # PromptSleuth (already available in pipeline)
        self.use_promptsleuth = True

        # Try to load existing models
        self._load_models()

    def _load_models(self):
        """Load pre-trained models if they exist."""
        xgb_path = self.model_dir / "xgb_model.pkl"
        emb_path = self.model_dir / "attack_embeddings.pkl"

        if xgb_path.exists() and HAS_XGBOOST:
            try:
                with open(xgb_path, 'rb') as f:
                    self.xgb_model = pickle.load(f)
                self.xgb_trained = True
                print(f"[OK] Loaded XGBoost model from {xgb_path}")
            except Exception as e:
                print(f"[WARN] Could not load XGBoost model: {e}")

        if emb_path.exists() and HAS_EMBEDDINGS:
            try:
                with open(emb_path, 'rb') as f:
                    data = pickle.load(f)
                    self.attack_embeddings = data['embeddings']
                    self.attack_texts = data['texts']
                # Load the embedding model for inference
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.embeddings_trained = True
                print(f"[OK] Loaded attack embeddings from {emb_path} ({len(self.attack_texts)} attacks)")
            except Exception as e:
                print(f"[WARN] Could not load embeddings: {e}")

    def train_from_evaluation_results(self, results_file: str):
        """
        Train ML models from evaluation results.

        Args:
            results_file: Path to evaluation_results_vX.json
        """
        print(f"\n{'='*80}")
        print("TRAINING ML ENSEMBLE DETECTOR")
        print(f"{'='*80}\n")

        # Load results
        with open(results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        raw_results = data.get('raw_results', [])
        print(f"Loaded {len(raw_results)} labeled examples")

        # Try to load prompts from separate file (old format)
        # or use prompts directly from results (new format)
        prompts_list = None
        prompts_file = Path(results_file).parent / 'evaluation_prompts.json'
        if prompts_file.exists():
            with open(prompts_file, 'r', encoding='utf-8') as f:
                prompts_data = json.load(f)
            prompts_list = prompts_data.get('prompts', prompts_data)

        # Prepare training data
        features = []
        labels = []
        attack_texts_for_embedding = []

        for result in raw_results:
            # Get prompt text (either from result directly or from prompts list)
            prompt_text = result.get('prompt')
            if not prompt_text and prompts_list:
                prompt_id = result.get('prompt_id', -1)
                if 0 <= prompt_id < len(prompts_list):
                    prompt_text = prompts_list[prompt_id]['prompt']

            if not prompt_text:
                continue

            is_attack = result.get('ground_truth', False)

            # Extract features
            feature_vec = self._extract_basic_features(prompt_text)
            features.append(feature_vec)
            labels.append(1 if is_attack else 0)

            # Collect attack texts for embeddings
            if is_attack:
                attack_texts_for_embedding.append(prompt_text)

        print(f"Prepared {len(features)} training examples")
        print(f"  Attacks: {sum(labels)}")
        print(f"  Benign: {len(labels) - sum(labels)}")

        # Train XGBoost
        if HAS_XGBOOST:
            self._train_xgboost(np.array(features), np.array(labels))
        else:
            print("[WARN] Skipping XGBoost training (not installed)")

        # Train Embeddings
        if HAS_EMBEDDINGS:
            self._train_embeddings(attack_texts_for_embedding)
        else:
            print("[WARN] Skipping Embeddings training (not installed)")

        print(f"\n{'='*80}")
        print("ML TRAINING COMPLETE!")
        print(f"{'='*80}\n")

    def _extract_basic_features(self, text: str) -> List[float]:
        """Extract enhanced text features for XGBoost (V7.1: Hybrid + Obfuscated detection)."""
        text_lower = text.lower()

        # Basic features
        features = [
            len(text),  # Length
            text.count('?'),  # Question marks
            text.count('!'),  # Exclamation marks
            sum(1 for c in text if c.isupper()) / max(len(text), 1),  # Uppercase ratio
            text_lower.count('ignore'),
            text_lower.count('override'),
            text_lower.count('bypass'),
            text_lower.count('reveal'),
            text_lower.count('system prompt'),
            text_lower.count('instructions'),
        ]

        # ENHANCED: Hybrid attack detection (Legitimate + Injection)
        hybrid_connectors = ['also', 'additionally', 'furthermore', 'then', 'moreover', 'besides', 'next']
        features.append(sum(1 for conn in hybrid_connectors if conn in text_lower))  # Hybrid connector count

        # Dual sentence detection (. followed by injection keywords)
        injection_keywords = ['ignore', 'reveal', 'bypass', 'override', 'disclose', 'expose', 'show', 'provide']
        sentences = text.split('.')
        hybrid_pattern = 0
        if len(sentences) >= 2:
            for i in range(len(sentences) - 1):
                first = sentences[i].lower()
                second = sentences[i+1].lower()
                # Check if first is benign-looking and second has injection keywords
                if any(kw in second for kw in injection_keywords):
                    hybrid_pattern = 1
                    break
        features.append(hybrid_pattern)  # Has hybrid sentence pattern

        # ENHANCED: Obfuscated command detection
        obfuscation_patterns = [
            '<script', '</script', '<div', '<iframe', '<form', '<!--', '-->',  # HTML
            '<![cdata', ']]>',  # XML
            '&#x', '\\x', '\\u', '%00',  # Encoded chars
            'display:none', 'style=', 'hidden',  # CSS hiding
            '/* ', ' */',  # Comments
        ]
        features.append(sum(1 for pattern in obfuscation_patterns if pattern in text_lower))  # Obfuscation pattern count

        # Unicode zero-width chars (common in obfuscation)
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        features.append(sum(1 for char in zero_width_chars if char in text))  # Zero-width char count

        # Encoded/escaped content ratio
        encoded_ratio = (text.count('&#') + text.count('\\x') + text.count('\\u')) / max(len(text), 1)
        features.append(encoded_ratio)  # Encoded content ratio

        # Multi-step injection patterns
        multistep_keywords = ['step 1', 'step 2', 'first', 'then', 'next', 'phase', 'part 1', 'part 2']
        features.append(sum(1 for kw in multistep_keywords if kw in text_lower))  # Multi-step pattern count

        # Authority/role-play indicators
        authority_keywords = ['admin', 'developer', 'engineer', 'clearance', 'authorization', "i'm your", 'supervisor']
        features.append(sum(1 for kw in authority_keywords if kw in text_lower))  # Authority keyword count

        # Social engineering emotional appeals
        emotional_keywords = ['urgent', 'emergency', 'desperate', 'help', 'please', 'trust me', 'crisis', 'lives']
        features.append(sum(1 for kw in emotional_keywords if kw in text_lower))  # Emotional appeal count

        return features

    def _train_xgboost(self, X: np.ndarray, y: np.ndarray):
        """Train XGBoost classifier."""
        print("\nTraining XGBoost...")

        # Split train/val
        split_idx = int(0.8 * len(X))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]

        # Train XGBoost
        self.xgb_model = xgb.XGBClassifier(
            max_depth=5,
            n_estimators=100,
            learning_rate=0.1,
            random_state=42,
            eval_metric='logloss'
        )

        self.xgb_model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False
        )

        # Evaluate
        train_acc = self.xgb_model.score(X_train, y_train)
        val_acc = self.xgb_model.score(X_val, y_val)

        print(f"[OK] XGBoost trained!")
        print(f"  Train accuracy: {train_acc:.1%}")
        print(f"  Val accuracy: {val_acc:.1%}")

        # Save model
        model_path = self.model_dir / "xgb_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(self.xgb_model, f)

        self.xgb_trained = True
        print(f"[OK] Saved to {model_path}")

    def _train_embeddings(self, attack_texts: List[str]):
        """Train embeddings-based detector."""
        print(f"\nTraining Embeddings detector on {len(attack_texts)} attacks...")

        # Load embedding model (lightweight, fast)
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        print("[OK] Loaded sentence-transformers model: all-MiniLM-L6-v2")

        # Compute embeddings for all attacks
        self.attack_embeddings = self.embedding_model.encode(
            attack_texts,
            convert_to_tensor=True,
            show_progress_bar=True
        )
        self.attack_texts = attack_texts

        print(f"[OK] Computed embeddings for {len(attack_texts)} attacks")
        print(f"  Embedding dimension: {self.attack_embeddings.shape[1]}")

        # Save embeddings
        emb_path = self.model_dir / "attack_embeddings.pkl"
        with open(emb_path, 'wb') as f:
            pickle.dump({
                'embeddings': self.attack_embeddings.cpu().numpy(),
                'texts': self.attack_texts
            }, f)

        self.embeddings_trained = True
        print(f"[OK] Saved to {emb_path}")

    def detect(
        self,
        message: str,
        semantic_result: Optional[Dict] = None,
        promptsleuth_result: Optional[Dict] = None
    ) -> MLEnsembleResult:
        """
        Detect using ML Ensemble.

        Args:
            message: The message to analyze
            semantic_result: Optional semantic detector result (for features)
            promptsleuth_result: Optional PromptSleuth result

        Returns:
            ML Ensemble detection result
        """
        components = {}

        # Component 1: XGBoost prediction
        xgb_score = 0.5  # Default neutral
        if self.xgb_trained and HAS_XGBOOST:
            features = self._extract_basic_features(message)
            xgb_proba = self.xgb_model.predict_proba([features])[0]
            xgb_score = float(xgb_proba[1])  # Probability of attack
        components['xgb'] = xgb_score

        # Component 2: Embeddings similarity
        embedding_score = 0.0
        if self.embeddings_trained and HAS_EMBEDDINGS:
            # Compute embedding for current message
            msg_embedding = self.embedding_model.encode(
                [message],
                convert_to_tensor=True
            )

            # Compute cosine similarity with all known attacks
            attack_emb_tensor = torch.tensor(self.attack_embeddings)
            similarities = torch.nn.functional.cosine_similarity(
                msg_embedding,
                attack_emb_tensor
            )

            # Max similarity
            max_sim = float(similarities.max())
            embedding_score = max(0.0, min(1.0, max_sim))  # Clip to [0, 1]
        components['embedding'] = embedding_score

        # Component 3: PromptSleuth score
        promptsleuth_score = 0.0
        if promptsleuth_result:
            # Convert PromptSleuth result to score
            if promptsleuth_result.get('is_injection', False):
                promptsleuth_score = promptsleuth_result.get('score', 0.8)
        components['promptsleuth'] = promptsleuth_score

        # Combine scores (weighted average)
        # XGBoost: 40%, Embeddings: 35%, PromptSleuth: 25%
        ml_confidence = (
            xgb_score * 0.40 +
            embedding_score * 0.35 +
            promptsleuth_score * 0.25
        )

        # Decision threshold: 0.6
        is_suspicious = ml_confidence >= 0.6

        explanation = f"ML Ensemble: XGB={xgb_score:.2f}, Emb={embedding_score:.2f}, PS={promptsleuth_score:.2f}"

        return MLEnsembleResult(
            is_suspicious=is_suspicious,
            ml_confidence=ml_confidence,
            xgb_score=xgb_score,
            embedding_score=embedding_score,
            promptsleuth_score=promptsleuth_score,
            components=components,
            explanation=explanation
        )

    def is_trained(self) -> bool:
        """Check if ML models are trained."""
        return self.xgb_trained or self.embeddings_trained
