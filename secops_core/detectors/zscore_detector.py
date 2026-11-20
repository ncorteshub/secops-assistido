import math
import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence


class ZScoreDetector:
    """
    Detector estatístico de anomalias volumétricas e temporais via Z-Score.
    Calcula Z = (x - mu) / sigma sobre métricas por evento e taxas agregadas
    por janela temporal (usuário/IP por minuto), preservando os dados originais.
    """

    DEFAULT_NUMERIC_FIELDS: Sequence[str] = (
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
        threshold: Optional[float] = None,
        numeric_fields: Optional[Sequence[str]] = None,
        time_bucket_seconds: int = 60,
    ) -> None:
        env_threshold = os.getenv("SECOPS_ZSCORE_THRESHOLD")
        if threshold is not None:
            self.threshold = float(threshold)
        elif env_threshold is not None:
            self.threshold = float(env_threshold)
        else:
            self.threshold = 3.0

        self.numeric_fields = tuple(numeric_fields or self.DEFAULT_NUMERIC_FIELDS)
        self.time_bucket_seconds = max(1, int(time_bucket_seconds))

    @staticmethod
    def _mean_and_std(values: Sequence[float]) -> tuple[float, float]:
        """Calcula média (mu) e desvio padrão populacional (sigma)."""
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return mean, math.sqrt(variance)

    @staticmethod
    def calculate_zscore(value: float, mean: float, std: float) -> float:
        """Calcula Z = (x - mu) / sigma com proteção contra sigma == 0."""
        if std == 0.0 or math.isclose(std, 0.0, abs_tol=1e-12):
            return 0.0
        return (value - mean) / std

    def _extract_time_bucket(self, raw_ts: Any) -> int:
        """Converte timestamp ISO/epoch em janela temporal discreta (ex: minuto)."""
        if isinstance(raw_ts, (int, float)):
            epoch = float(raw_ts)
        elif isinstance(raw_ts, datetime):
            epoch = raw_ts.timestamp()
        elif isinstance(raw_ts, str):
            cleaned = raw_ts.replace("Z", "+00:00")
            try:
                epoch = datetime.fromisoformat(cleaned).timestamp()
            except ValueError:
                return 0
        else:
            return 0
        return int(epoch // self.time_bucket_seconds)

    def detect_series(self, values: Sequence[float]) -> List[Dict[str, Any]]:
        """
        Calcula Z-Score diretamente sobre uma série numérica simples.
        Útil para análises univariadas e testes diretos de séries temporais.
        """
        if not values:
            return []

        mean, std = self._mean_and_std(values)
        results: List[Dict[str, Any]] = []
        for val in values:
            z = self.calculate_zscore(float(val), mean, std)
            results.append(
                {
                    "value": val,
                    "zscore_value": round(z, 6),
                    "is_zscore_anomaly": abs(z) > self.threshold,
                }
            )
        return results

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analisa um lote de eventos normalizados sem mutar os dicionários originais.
        Combina Z-Score de:
          1) Taxa de eventos por (source_ip, janela_tempo)
          2) Taxa de eventos por (user_identity, janela_tempo)
          3) Métricas numéricas presentes nos eventos (bytes, latência, etc.)
        """
        if not events:
            return []

        # 1. Contagem temporal agregada por IP e por Usuário
        ip_bucket_keys: List[Optional[tuple[str, int]]] = []
        user_bucket_keys: List[Optional[tuple[str, int]]] = []
        ip_counts: Counter[tuple[str, int]] = Counter()
        user_counts: Counter[tuple[str, int]] = Counter()

        for ev in events:
            bucket = self._extract_time_bucket(ev.get("timestamp"))
            src_ip = ev.get("source_ip")
            user = ev.get("user_identity")

            if src_ip:
                ip_key = (str(src_ip), bucket)
                ip_bucket_keys.append(ip_key)
                ip_counts[ip_key] += 1
            else:
                ip_bucket_keys.append(None)

            if user:
                user_key = (str(user), bucket)
                user_bucket_keys.append(user_key)
                user_counts[user_key] += 1
            else:
                user_bucket_keys.append(None)

        ip_mean, ip_std = self._mean_and_std(list(ip_counts.values()))
        user_mean, user_std = self._mean_and_std(list(user_counts.values()))

        # 2. Estatísticas de campos numéricos presentes nos eventos
        field_stats: Dict[str, tuple[float, float]] = {}
        for field in self.numeric_fields:
            vals = [
                float(ev[field])
                for ev in events
                if field in ev and isinstance(ev[field], (int, float)) and not isinstance(ev[field], bool)
            ]
            if len(vals) >= 2:
                field_stats[field] = self._mean_and_std(vals)

        # 3. Enriquecimento sem mutar os eventos originais
        enriched_events: List[Dict[str, Any]] = []
        for idx, ev in enumerate(events):
            candidate_zscores: List[float] = [0.0]

            ip_key = ip_bucket_keys[idx]
            if ip_key is not None:
                candidate_zscores.append(
                    self.calculate_zscore(float(ip_counts[ip_key]), ip_mean, ip_std)
                )

            user_key = user_bucket_keys[idx]
            if user_key is not None:
                candidate_zscores.append(
                    self.calculate_zscore(float(user_counts[user_key]), user_mean, user_std)
                )

            for field, (f_mean, f_std) in field_stats.items():
                val = ev.get(field)
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    candidate_zscores.append(
                        self.calculate_zscore(float(val), f_mean, f_std)
                    )

            # Seleciona o Z-Score de maior magnitude absoluta
            dominant_z = max(candidate_zscores, key=lambda z: abs(z))

            # Cópia rasa preserva intacto o dicionário original passado como entrada
            ev_copy = dict(ev)
            ev_copy["zscore_value"] = round(dominant_z, 6)
            ev_copy["is_zscore_anomaly"] = abs(dominant_z) > self.threshold
            enriched_events.append(ev_copy)

        return enriched_events