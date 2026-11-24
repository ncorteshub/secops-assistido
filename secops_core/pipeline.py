import argparse
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from secops_core.db import SecOpsRepository
from secops_core.detectors.cloudtrail_rules import (
    CloudTrailRuleEngine,
    RuleViolation,
    Severity,
)
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.zscore_detector import ZScoreDetector
from secops_core.lgms import CanonicalLog, LGMSProcessor


class DetectionResult(BaseModel):
    event_id: str
    timestamp: Optional[str] = None
    event_source: Optional[str] = None
    event_name: Optional[str] = None
    is_anomaly: bool
    severity: Severity
    triggered_detectors: List[str] = Field(default_factory=list)
    rule_violations: List[RuleViolation] = Field(default_factory=list)
    zscore_anomaly: bool = False
    zscore_value: Optional[float] = None
    isolation_forest_anomaly: bool = False
    isolation_forest_score: Optional[float] = None
    technical_justification: str
    raw_event: Dict[str, Any] = Field(default_factory=dict)

    def to_db_record(self) -> Dict[str, Any]:
        """Converte o resultado consolidado para o formato aceito pelo SecOpsRepository."""
        record = dict(self.raw_event)
        record.update(
            {
                "event_id": self.event_id,
                "timestamp": self.timestamp,
                "event_source": self.event_source,
                "event_name": self.event_name,
                "is_anomaly": self.is_anomaly,
                "severity": self.severity.value,
                "triggered_detectors": self.triggered_detectors,
                "rule_violations": [v.model_dump() for v in self.rule_violations],
                "zscore_anomaly": self.zscore_anomaly,
                "zscore_value": self.zscore_value,
                "isolation_forest_anomaly": self.isolation_forest_anomaly,
                "isolation_forest_score": self.isolation_forest_score,
                "technical_justification": self.technical_justification,
                "anomaly_reason": self.technical_justification,
            }
        )
        return record


class HybridSecOpsPipeline:
    """
    Orquestrador ponta a ponta do SecOps Assistido:
    JSONL -> LGMSProcessor -> (ZScoreDetector + IsolationForestDetector + CloudTrailRuleEngine)
          -> Consolidação de Severidade -> SecOpsRepository (SQLite)
    """

    SEVERITY_RANK = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def __init__(
        self,
        db_path: str = "data/secops.db",
        zscore_detector: Optional[ZScoreDetector] = None,
        iforest_detector: Optional[IsolationForestDetector] = None,
        rule_engine: Optional[CloudTrailRuleEngine] = None,
        repository: Optional[SecOpsRepository] = None,
        zscore_runner: Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None,
        iforest_runner: Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None,
    ) -> None:
        self.db_path = db_path
        self.zscore_detector = zscore_detector or ZScoreDetector()
        self.iforest_detector = iforest_detector or IsolationForestDetector()
        self.rule_engine = rule_engine or CloudTrailRuleEngine()
        self.repository = repository or SecOpsRepository(db_path=db_path)

        self._zscore_runner = zscore_runner or self.zscore_detector.detect
        self._iforest_runner = iforest_runner or self.iforest_detector.fit_predict

    def _normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Valida via CanonicalLog do LGMS mantendo compatibilidade com eventos brutos."""
        try:
            canonical = CanonicalLog(**raw_event)
            return canonical.model_dump(mode="json")
        except Exception:
            return dict(raw_event)

    def _consolidate_severity_and_reason(
        self,
        zscore_flag: bool,
        zscore_val: Optional[float],
        iforest_flag: bool,
        iforest_score: Optional[float],
        violations: List[RuleViolation],
    ) -> Tuple[bool, Severity, List[str], str]:
        triggered: List[str] = []
        reasons: List[str] = []

        if violations:
            triggered.append("CLOUDTRAIL_RULES")
            rule_codes = ", ".join(v.rule_code for v in violations)
            rule_details = " | ".join(f"[{v.rule_code}] {v.technical_reason}" for v in violations)
            reasons.append(f"Regras determinísticas acionadas ({rule_codes}): {rule_details}")

        if zscore_flag:
            triggered.append("Z_SCORE")
            z_str = f" (z={zscore_val:.2f})" if isinstance(zscore_val, (int, float)) else ""
            reasons.append(f"Desvio estatístico univariado detectado pelo Z-Score{z_str}.")

        if iforest_flag:
            triggered.append("ISOLATION_FOREST")
            s_str = f" (score={iforest_score:.4f})" if isinstance(iforest_score, (int, float)) else ""
            reasons.append(f"Anomalia comportamental multivariada detectada pelo Isolation Forest{s_str}.")

        is_anomaly = len(triggered) > 0

        if not is_anomaly:
            return (
                False,
                Severity.LOW,
                [],
                "Nenhuma anomalia estatística, comportamental ou violação de regra detectada.",
            )

        highest_severity = Severity.LOW
        for v in violations:
            if self.SEVERITY_RANK[v.severity] > self.SEVERITY_RANK[highest_severity]:
                highest_severity = v.severity

        if zscore_flag and iforest_flag and violations:
            highest_severity = Severity.CRITICAL
        elif zscore_flag and iforest_flag:
            if self.SEVERITY_RANK[Severity.HIGH] > self.SEVERITY_RANK[highest_severity]:
                highest_severity = Severity.HIGH
        elif zscore_flag or iforest_flag:
            if self.SEVERITY_RANK[Severity.MEDIUM] > self.SEVERITY_RANK[highest_severity]:
                highest_severity = Severity.MEDIUM

        return True, highest_severity, triggered, " ".join(reasons)

    def _build_context_windows(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calcula janelas de contagem para regras stateful (ConsoleLogin e AccessDenied)."""
        failed_logins_by_ip: Dict[str, int] = {}
        denied_by_arn: Dict[str, int] = {}

        for ev in events:
            event_name = ev.get("event_name") or ev.get("eventName")
            status = str(ev.get("status", "")).lower()
            resp = ev.get("response_elements") or ev.get("responseElements") or {}
            ip = ev.get("source_ip") or ev.get("sourceIPAddress") or "unknown"
            identity = ev.get("user_identity") or ev.get("userIdentity") or {}
            arn = identity.get("arn", "unknown") if isinstance(identity, dict) else "unknown"
            error_code = ev.get("error_code") or ev.get("errorCode")

            if event_name == "ConsoleLogin" and (resp.get("ConsoleLogin") == "Failure" or status in {"failure", "failed", "error"}):
                failed_logins_by_ip[ip] = failed_logins_by_ip.get(ip, 0) + 1

            if error_code in {"AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation"}:
                denied_by_arn[arn] = denied_by_arn.get(arn, 0) + 1

        contexts: List[Dict[str, Any]] = []
        for ev in events:
            ip = ev.get("source_ip") or ev.get("sourceIPAddress") or "unknown"
            identity = ev.get("user_identity") or ev.get("userIdentity") or {}
            arn = identity.get("arn", "unknown") if isinstance(identity, dict) else "unknown"
            contexts.append(
                {
                    "failed_console_logins_window": failed_logins_by_ip.get(ip, 0),
                    "access_denied_count_window": denied_by_arn.get(arn, 0),
                }
            )
        return contexts

    def run_events(
        self, raw_events: List[Dict[str, Any]], persist: bool = True
    ) -> List[DetectionResult]:
        if not raw_events:
            return []

        normalized_events = [self._normalize_event(ev) for ev in raw_events]

        zscore_outputs = self._zscore_runner(normalized_events)
        iforest_outputs = self._iforest_runner(normalized_events)
        contexts = self._build_context_windows(normalized_events)

        results: List[DetectionResult] = []
        for idx, (raw_ev, norm_ev) in enumerate(zip(raw_events, normalized_events)):
            z_out = zscore_outputs[idx] if idx < len(zscore_outputs) else {}
            if_out = iforest_outputs[idx] if idx < len(iforest_outputs) else {}

            z_flag = bool(
                z_out.get("zscore_anomaly")
                or z_out.get("is_zscore_anomaly")
                or z_out.get("is_anomaly", False)
            )
            z_val = (
                z_out.get("zscore_value")
                if z_out.get("zscore_value") is not None
                else z_out.get("max_zscore")
                if z_out.get("max_zscore") is not None
                else z_out.get("zscore")
            )

            if_flag = bool(
                if_out.get("isolation_forest_anomaly")
                or if_out.get("is_iforest_anomaly")
                or if_out.get("is_anomaly", False)
            )
            if_score = (
                if_out.get("isolation_forest_score")
                if if_out.get("isolation_forest_score") is not None
                else if_out.get("anomaly_score")
            )

            violations = self.rule_engine.evaluate(norm_ev, context=contexts[idx])

            is_anomaly, severity, triggered, justification = self._consolidate_severity_and_reason(
                zscore_flag=z_flag,
                zscore_val=z_val,
                iforest_flag=if_flag,
                iforest_score=if_score,
                violations=violations,
            )

            event_id = str(
                norm_ev.get("event_id")
                or norm_ev.get("eventID")
                or raw_ev.get("event_id")
                or raw_ev.get("eventID")
                or f"evt-{idx}"
            )

            ts = norm_ev.get("timestamp") or norm_ev.get("eventTime")
            if ts is not None and not isinstance(ts, str):
                ts = ts.isoformat()

            results.append(
                DetectionResult(
                    event_id=event_id,
                    timestamp=ts,
                    event_source=norm_ev.get("event_source") or norm_ev.get("eventSource"),
                    event_name=norm_ev.get("event_name") or norm_ev.get("eventName"),
                    is_anomaly=is_anomaly,
                    severity=severity,
                    triggered_detectors=triggered,
                    rule_violations=violations,
                    zscore_anomaly=z_flag,
                    zscore_value=z_val,
                    isolation_forest_anomaly=if_flag,
                    isolation_forest_score=if_score,
                    technical_justification=justification,
                    raw_event=raw_ev,
                )
            )

        if persist:
            self.repository.init_db()
            self.repository.bulk_insert([r.to_db_record() for r in results])

        return results

    def run_from_jsonl(self, input_path: str, persist: bool = True) -> List[DetectionResult]:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Arquivo de logs não encontrado: {input_path}")

        processor = LGMSProcessor(str(path))
        parsed = processor.parse_file()
        canonical_logs = (
            parsed
            or getattr(processor, "parsed_logs", None)
            or getattr(processor, "valid_logs", None)
            or getattr(processor, "logs", None)
            or getattr(processor, "records", None)
            or []
        )
        events = [
            log.model_dump(mode="json") if hasattr(log, "model_dump") else dict(log)
            for log in canonical_logs
        ]
        return self.run_events(events, persist=persist)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa o pipeline híbrido de detecção SecOps Assistido."
    )
    parser.add_argument(
        "--input",
        "-i",
        default="data/logs_simulados.jsonl",
        help="Caminho para o arquivo JSONL de entrada (padrão: data/logs_simulados.jsonl).",
    )
    parser.add_argument(
        "--db",
        default="data/secops.db",
        help="Caminho para o banco SQLite de saída (padrão: data/secops.db).",
    )
    args = parser.parse_args()

    pipeline = HybridSecOpsPipeline(db_path=args.db)
    results = pipeline.run_from_jsonl(args.input, persist=True)

    anomalies = [r for r in results if r.is_anomaly]
    print(f"[SecOps Pipeline] Total de eventos processados : {len(results)}")
    print(f"[SecOps Pipeline] Anomalias detectadas        : {len(anomalies)}")
    print(f"[SecOps Pipeline] Banco SQLite atualizado em  : {args.db}")

    for alert in anomalies[:10]:
        print(
            f"  -> [{alert.severity.value}] {alert.event_id} ({alert.event_name}) "
            f"| Detectores: {', '.join(alert.triggered_detectors)}"
        )


if __name__ == "__main__":
    main()