"""
Machine Learning module for DDoS Detection
Role: Confidence-based support for rule-based detection
"""

import pickle
import numpy as np
import pandas as pd
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class MLModel:
    """
    ML Model used as a CONFIDENCE PROVIDER.
    It never directly declares an attack.
    """

    def __init__(self, model_path: str = "models/ddos_rf.pkl"):
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = StandardScaler()
        self.is_loaded = False

        # Confidence thresholds
        self.TH_ATTACK = 0.80
        self.TH_SUSPICIOUS = 0.60

        # Feature list (must match feature extractor)
        self.features = [
            'packet_rate', 'byte_rate', 'src_ip_entropy',
            'dst_ip_entropy', 'src_port_entropy', 'dst_port_entropy',
            'protocol_entropy', 'packet_size_mean', 'packet_size_std',
            'inter_arrival_mean', 'inter_arrival_std',
            'tcp_syn_ratio', 'tcp_ack_ratio', 'udp_ratio',
            'icmp_ratio', 'src_ip_count', 'dst_ip_count',
            'connection_rate', 'duration'
        ]

    # --------------------------------------------------
    # MODEL LOADING
    # --------------------------------------------------
    async def load_model(self):
        if self.model_path.exists():
            loop = asyncio.get_event_loop()
            self.model, self.scaler = await loop.run_in_executor(
                None, self._load_from_disk
            )
            self.is_loaded = True
            logger.info("ML model loaded successfully")
        else:
            logger.warning("Model not found. Training default model.")
            await self._train_default_model()

    def _load_from_disk(self):
        with open(self.model_path, "rb") as f:
            return pickle.load(f)

    # --------------------------------------------------
    # DEFAULT TRAINING (SYNTHETIC)
    # --------------------------------------------------
    async def _train_default_model(self):
        X, y = self._generate_synthetic_data()

        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        self.model = RandomForestClassifier(
            n_estimators=120,
            max_depth=12,
            random_state=42,
            n_jobs=-1
        )

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.model.fit, X_scaled, y)

        await self._save_model()
        self.is_loaded = True
        logger.info("Default ML model trained")

    def _generate_synthetic_data(self) -> Tuple[np.ndarray, np.ndarray]:
        n = 12000
        f = len(self.features)

        normal = np.random.normal(0.35, 0.15, (n // 2, f))
        attack = np.random.normal(0.75, 0.20, (n // 2, f))

        X = np.vstack((normal, attack))
        y = np.hstack((np.zeros(n // 2), np.ones(n // 2)))

        idx = np.random.permutation(len(X))
        return X[idx], y[idx]

    async def _save_model(self):
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: pickle.dump((self.model, self.scaler), open(self.model_path, "wb"))
        )

    # --------------------------------------------------
    # PREDICTION
    # --------------------------------------------------
    async def predict(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Returns confidence + risk level only
        """
        if not self.is_loaded or self.model is None:
            return self._neutral_response()

        try:
            X = np.array([[feature_dict.get(f, 0.0) for f in self.features]])
            X_scaled = self.scaler.transform(X)

            confidence = float(self.model.predict_proba(X_scaled)[0][1])

            # Damp overconfidence
            confidence = min(confidence * 0.95, 0.95)

            if confidence >= self.TH_ATTACK:
                risk = "high"
            elif confidence >= self.TH_SUSPICIOUS:
                risk = "medium"
            else:
                risk = "low"

            return {
                "confidence": round(confidence, 3),
                "risk_level": risk
            }

        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._neutral_response()

    def _neutral_response(self):
        return {"confidence": 0.5, "risk_level": "unknown"}

    # --------------------------------------------------
    # BATCH PREDICTION
    # --------------------------------------------------
    async def predict_batch(self, df: pd.DataFrame) -> List[float]:
        if not self.is_loaded or self.model is None:
            return [0.5] * len(df)

        X = df[self.features].values
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)[:, 1]
        return probs.tolist()

    # --------------------------------------------------
    # INFO FOR DASHBOARD
    # --------------------------------------------------
    def get_model_info(self) -> Dict[str, Any]:
        if not self.is_loaded:
            return {"status": "not_loaded"}

        return {
            "status": "loaded",
            "model": "RandomForest",
            "features": len(self.features),
            "attack_threshold": self.TH_ATTACK,
            "suspicious_threshold": self.TH_SUSPICIOUS
        }
