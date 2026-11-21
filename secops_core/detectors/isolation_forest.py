from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IsolationForestDetector:
    """
    Detector multivariado não supervisionado baseado em Isolation Forest.
    Extrai features temporais, frequência de variáveis categóricas e métricas
    numéricas dos logs LGMS, preservando os dicionários originais.
    """

    CATEGORICAL_FIELDS: Sequence[str] = (
        "event_name",
        "event_source",
        "source_ip",
        "user_identity",
        "aws_region",
    )

    NUMERIC_FIELDS: Sequence[str] = (
        "bytes_transferred",
        "bytes_out",
        "bytes_in",
        "latency_ms",
        "duration_ms",
        "error_count",
        "request_count",
    )

    def __init__(
        self,
        contamination: float | str = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
        categorical_fields: Optional[Sequence[str]] = None,
        numeric_fields: Optional[Sequence[str]] = None,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = int(n_estimators)
        self.random_state = int(random_state)
        self.categorical_fields = tuple(categorical_fields or self.CATEGORICAL_FIELDS)
        self.numeric_fields = tuple(numeric_fields or self.NUMERIC_FIELDS)

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=1,  # Execução leve e determinística em CPU
        )
        self._category_freqs: Dict[str, Dict[str, float]] = {}
        self._is_fitted = False

    @staticmethod
    def _parse_temporal_features(raw_ts: Any) -> tuple[float, float]:
        """Extrai (hora_do_dia, dia_da_semana) a partir de timestamp ISO/epoch."""
        dt: Optional[datetime] = None
        if isinstance(raw_ts, datetime):
            dt = raw_ts
        elif isinstance(raw_ts, (int, float)):
            dt = datetime.fromtimestamp(float(raw_ts))
        elif isinstance(raw_ts, str):
            cleaned = raw_ts.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(cleaned)
            except ValueError:
                dt = None

        if dt is None:
            return 0.0, 0.0
        return float(dt.hour), float(dt.weekday())

    def _compute_category_frequencies(self, events: List[Dict[str, Any]]) -> None:
        """Calcula frequência relativa de cada categoria no lote de treino."""
        total = max(1, len(events))
        self._category_freqs = {}
        for field in self.categorical_fields:
            counts = Counter(str(ev.get(field) or "UNKNOWN") for ev in events)
            self._category_freqs[field] = {
                key: count / total for key, count in counts.items()
            }

    def _build_feature_matrix(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Constrói matriz numérica (N_eventos x N_features) a partir dos logs LGMS."""
        rows: List[List[float]] = []

        for ev in events:
            hour, weekday = self._parse_temporal_features(ev.get("timestamp"))
            row: List[float] = [hour, weekday]

            # Frequency encoding para variáveis categóricas
            for field in self.categorical_fields:
                val = str(ev.get(field) or "UNKNOWN")
                freq_map = self._category_freqs.get(field, {})
                # Categorias inéditas na inferência recebem frequência mínima (0.0)
                row.append(freq_map.get(val, 0.0))

            # Campos numéricos (fallback 0.0 se ausente)
            for field in self.numeric_fields:
                raw_val = ev.get(field)
                if isinstance(raw_val, (int, float)) and not isinstance(raw_val, bool):
                    row.append(float(raw_val))
                else:
                    row.append(0.0)

            rows.append(row)

        return np.asarray(rows, dtype=np.float64)

    def fit(self, events: List[Dict[str, Any]]) -> "IsolationForestDetector":
        """Treina o escalonador e o Isolation Forest sobre um lote de logs LGMS."""
        if not events:
            raise ValueError("Não é possível treinar IsolationForestDetector com lista vazia.")

        self._compute_category_frequencies(events)
        raw_matrix = self._build_feature_matrix(events)
        scaled_matrix = self.scaler.fit_transform(raw_matrix)

        self.model.fit(scaled_matrix)
        self._is_fitted = True
        return self

    def predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Infere anomalias em eventos já com modelo treinado.
        Retorna cópias enriquecidas com `iforest_score` e `is_iforest_anomaly`.
        """
        if not events:
            return []
        if not self._is_fitted:
            raise RuntimeError("O modelo precisa ser treinado com fit() antes de chamar predict().")

        raw_matrix = self._build_feature_matrix(events)
        scaled_matrix = self.scaler.transform(raw_matrix)

        # decision_function: valores menores/negativos = mais anômalos
        scores = self.model.decision_function(scaled_matrix)
        # predict: -1 = anomalia, 1 = normal
        predictions = self.model.predict(scaled_matrix)

        enriched: List[Dict[str, Any]] = []
        for ev, score, pred in zip(events, scores, predictions):
            ev_copy = dict(ev)
            ev_copy["iforest_score"] = round(float(score), 6)
            ev_copy["is_iforest_anomaly"] = bool(int(pred) == -1)
            enriched.append(ev_copy)

        return enriched

    def fit_predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Treina e infere sobre o mesmo lote de eventos em uma única etapa."""
        if not events:
            return []
        self.fit(events)
        return self.predict(events)