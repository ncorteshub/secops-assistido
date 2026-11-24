"""Testes da camada de Detecção: Z-Score, Isolation Forest, CloudTrail Rules e Pipeline Híbrido."""

import copy
from pathlib import Path

import pytest

from secops_core.detectors.cloudtrail_rules import (
    CloudTrailRuleEngine,
    RuleViolation,
    Severity,
)
from secops_core.detectors.isolation_forest import IsolationForestDetector
from secops_core.detectors.zscore_detector import ZScoreDetector
from secops_core.pipeline import HybridSecOpsPipeline


def _build_isolation_forest_events():
    """Gera 45 eventos basais homogêneos e 2 eventos furtivos multivariados."""
    baseline = [
        {
            "event_id": f"base-{i}",
            "timestamp": f"2026-11-20T14:{i % 60:02d}:00Z",
            "source_ip": "10.0.1.15",
            "user_identity": "deploy-bot",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "aws_region": "us-east-1",
            "bytes_transferred": 2048 + (i % 50),
            "latency_ms": 45 + (i % 10),
        }
        for i in range(45)
    ]
    anomalies = [
        {
            "event_id": "stealth-1",
            "timestamp": "2026-11-20T03:17:00Z",
            "source_ip": "185.220.101.4",
            "user_identity": "root-legacy",
            "event_name": "CreateAccessKey",
            "event_source": "iam.amazonaws.com",
            "aws_region": "ap-southeast-3",
            "bytes_transferred": 9800,
            "latency_ms": 410,
        },
        {
            "event_id": "stealth-2",
            "timestamp": "2026-11-20T03:19:00Z",
            "source_ip": "185.220.101.4",
            "user_identity": "root-legacy",
            "event_name": "StopLogging",
            "event_source": "cloudtrail.amazonaws.com",
            "aws_region": "ap-southeast-3",
            "bytes_transferred": 11200,
            "latency_ms": 390,
        },
    ]
    return baseline + anomalies


class TestZScoreDetector:
    """Valida o detector estatístico univariado (Z-Score)."""

    def test_zscore_normal_distribution_no_anomalies(self):
        detector = ZScoreDetector(threshold=3.0)
        normal_series = [10, 11, 9, 10, 12, 10, 9, 11, 10, 10]
        results = detector.detect_series(normal_series)

        assert len(results) == len(normal_series)
        assert all(not item["is_zscore_anomaly"] for item in results)

    def test_zscore_extreme_spike_detection_and_immutability(self):
        detector = ZScoreDetector(threshold=3.0)
        events = [
            {
                "event_id": f"evt-{i}",
                "timestamp": f"2026-11-20T18:{i:02d}:00Z",
                "source_ip": f"10.0.0.{i + 1}",
                "user_identity": f"user-{i}",
                "bytes_transferred": 1024,
            }
            for i in range(20)
        ]
        events.append(
            {
                "event_id": "evt-exfil",
                "timestamp": "2026-11-20T18:25:00Z",
                "source_ip": "10.0.0.99",
                "user_identity": "compromised-user",
                "bytes_transferred": 50_000_000,
            }
        )

        snapshot = copy.deepcopy(events)
        enriched = detector.detect(events)

        assert events == snapshot
        assert enriched[-1]["event_id"] == "evt-exfil"
        assert enriched[-1]["is_zscore_anomaly"] is True
        assert enriched[-1]["zscore_value"] > 3.0
        assert all(item["is_zscore_anomaly"] is False for item in enriched[:-1])

    def test_zscore_zero_standard_deviation_protection(self):
        detector = ZScoreDetector(threshold=3.0)
        constant_events = [
            {
                "event_id": f"evt-{i}",
                "timestamp": f"2026-11-20T18:{i:02d}:00Z",
                "source_ip": "192.168.1.10",
                "user_identity": "service-account",
                "bytes_transferred": 500,
            }
            for i in range(5)
        ]

        enriched = detector.detect(constant_events)
        assert all(item["zscore_value"] == 0.0 for item in enriched)
        assert all(item["is_zscore_anomaly"] is False for item in enriched)

    def test_zscore_configurable_threshold_via_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECOPS_ZSCORE_THRESHOLD", "1.5")
        detector = ZScoreDetector()
        assert detector.threshold == 1.5

        results = detector.detect_series([10, 10, 10, 10, 25])
        assert results[-1]["is_zscore_anomaly"] is True


class TestIsolationForestDetector:
    """Valida o detector comportamental multivariado (Isolation Forest)."""

    def test_isolation_forest_detects_multivariate_anomalies_and_preserves_input(self):
        events = _build_isolation_forest_events()
        snapshot = copy.deepcopy(events)

        detector = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)
        results = detector.fit_predict(events)

        assert events == snapshot
        assert len(results) == len(events)

        baseline_scores = [r["iforest_score"] for r in results[:-2]]
        avg_baseline_score = sum(baseline_scores) / len(baseline_scores)

        for item in results[-2:]:
            assert item["is_iforest_anomaly"] is True
            assert item["iforest_score"] < avg_baseline_score

    def test_isolation_forest_reproducibility_with_fixed_random_state(self):
        events = _build_isolation_forest_events()
        det_a = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)
        det_b = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)

        res_a = det_a.fit_predict(events)
        res_b = det_b.fit_predict(events)

        assert [r["iforest_score"] for r in res_a] == [r["iforest_score"] for r in res_b]
        assert [r["is_iforest_anomaly"] for r in res_a] == [r["is_iforest_anomaly"] for r in res_b]

    def test_isolation_forest_edge_cases(self):
        detector = IsolationForestDetector()
        assert detector.fit_predict([]) == []

        with pytest.raises(ValueError):
            detector.fit([])

        with pytest.raises(RuntimeError):
            detector.predict([{"event_name": "GetObject"}])


class TestCloudTrailRules:
    """Valida o motor de regras determinísticas de segurança AWS CloudTrail."""

    @pytest.fixture
    def engine(self) -> CloudTrailRuleEngine:
        return CloudTrailRuleEngine()

    def test_clean_event_returns_empty_list(self, engine: CloudTrailRuleEngine):
        benign_event = {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/dev"},
            "sourceIPAddress": "10.0.0.15",
        }
        assert engine.evaluate(benign_event) == []

    def test_rule_trail_tampering(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "userIdentity": {"type": "IAMUser"},
            "requestParameters": {"name": "corp-audit-trail"},
        }
        violations = engine.evaluate(event)
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_TRAIL_TAMPERING"
        assert violations[0].severity == Severity.CRITICAL
        assert "StopLogging" in violations[0].technical_reason

    def test_rule_root_activity(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.42",
        }
        violations = engine.evaluate(event)
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_ROOT_ACTIVITY"
        assert violations[0].severity == Severity.CRITICAL

    def test_rule_iam_privilege_escalation(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser"},
            "requestParameters": {
                "userName": "estagiario",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        }
        violations = engine.evaluate(event)
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_IAM_PRIVILEGE_ESCALATION"
        assert violations[0].severity == Severity.CRITICAL

    def test_rule_sensitive_s3_public_access(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteBucketPublicAccessBlock",
            "userIdentity": {"type": "AssumedRole"},
            "requestParameters": {"bucketName": "dados-clientes-prod"},
        }
        violations = engine.evaluate(event)
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_SENSITIVE_S3_PUBLIC_ACCESS"
        assert violations[0].severity == Severity.HIGH

    def test_rule_brute_force_console(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/admin"},
            "sourceIPAddress": "198.51.100.10",
            "responseElements": {"ConsoleLogin": "Failure"},
        }
        assert engine.evaluate(event, context={"failed_console_logins_window": 2}) == []

        violations = engine.evaluate(event, context={"failed_console_logins_window": 5})
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_BRUTE_FORCE_CONSOLE"
        assert violations[0].severity == Severity.HIGH

    def test_rule_unauthorized_api_burst(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "secretsmanager.amazonaws.com",
            "eventName": "GetSecretValue",
            "errorCode": "AccessDenied",
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/app/i-1",
            },
        }
        violations = engine.evaluate(event, context={"access_denied_count_window": 12})
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_UNAUTHORIZED_API_BURST"
        assert violations[0].severity == Severity.MEDIUM

    def test_multiple_rules_triggered_simultaneously(self, engine: CloudTrailRuleEngine):
        event = {
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "DeleteTrail",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "192.0.2.1",
            "requestParameters": {"name": "main-trail"},
        }
        violations = engine.evaluate(event)
        assert {v.rule_code for v in violations} == {
            "RULE_ROOT_ACTIVITY",
            "RULE_TRAIL_TAMPERING",
        }

    def test_extensibility_with_custom_rule_engine(self):
        custom_rules = []

        def local_register(fn):
            custom_rules.append(fn)
            return fn

        @local_register
        def rule_kms_key_deletion(event, context=None):
            if event.get("eventName") == "ScheduleKeyDeletion":
                return RuleViolation(
                    rule_code="RULE_KMS_KEY_DELETION",
                    name="Agendamento de Exclusão de Chave KMS",
                    severity=Severity.CRITICAL,
                    technical_reason="Chave KMS agendada para exclusão.",
                )
            return None

        custom_engine = CloudTrailRuleEngine(rules=custom_rules)
        violations = custom_engine.evaluate({"eventName": "ScheduleKeyDeletion"})
        assert len(violations) == 1
        assert violations[0].rule_code == "RULE_KMS_KEY_DELETION"


class TestHybridPipelineEnsemble:
    """Valida os 3 detectores atuando em conjunto no HybridSecOpsPipeline."""

    def test_hybrid_pipeline_runs_all_detectors_together_and_persists(
        self, test_db_path: Path, test_logs_path: Path
    ):
        import json

        events = [
            {
                "event_id": f"norm-{i}",
                "timestamp": f"2026-11-24T14:{i:02d}:00Z",
                "event_source": "ec2.amazonaws.com",
                "event_name": "DescribeInstances",
                "user_identity": {"arn": f"arn:aws:iam::123456789012:user/dev-{i}"},
                "source_ip": f"10.0.0.{i + 1}",
                "aws_region": "us-east-1",
                "status": "Success",
                "error_code": None,
                "request_count": 2,
                "bytes_transferred": 1024,
            }
            for i in range(25)
        ]
        # Anomalia crítica híbrida: Root + DeleteTrail + pico extremo de bytes/requests
        events.append(
            {
                "event_id": "evt-hybrid-critical",
                "timestamp": "2026-11-24T03:05:00Z",
                "event_source": "cloudtrail.amazonaws.com",
                "event_name": "DeleteTrail",
                "user_identity": {"arn": "arn:aws:iam::123456789012:root"},
                "source_ip": "185.15.59.22",
                "aws_region": "us-east-1",
                "status": "Success",
                "error_code": None,
                "request_count": 1500,
                "bytes_transferred": 9_500_000,
            }
        )

        test_logs_path.write_text(
            "\n".join(json.dumps(ev) for ev in events) + "\n",
            encoding="utf-8",
        )

        pipeline = HybridSecOpsPipeline(
            db_path=str(test_db_path),
            zscore_detector=ZScoreDetector(threshold=3.0),
            iforest_detector=IsolationForestDetector(contamination=0.05, random_state=42),
        )
        results = pipeline.run_from_jsonl(str(test_logs_path), persist=True)

        assert len(results) == 26
        by_id = {r.event_id: r for r in results}

        normal_sample = by_id["norm-0"]
        assert normal_sample.is_anomaly is False
        assert normal_sample.severity == Severity.LOW
        assert normal_sample.triggered_detectors == []

        hybrid = by_id["evt-hybrid-critical"]
        assert hybrid.is_anomaly is True
        assert hybrid.severity == Severity.CRITICAL
        assert "CLOUDTRAIL_RULES" in hybrid.triggered_detectors
        assert "Z_SCORE" in hybrid.triggered_detectors
        assert hybrid.zscore_anomaly is True
        assert {v.rule_code for v in hybrid.rule_violations} == {
            "RULE_ROOT_ACTIVITY",
            "RULE_TRAIL_TAMPERING",
        }

        persisted = pipeline.repository.query_alerts(only_anomalies=False, limit=100)
        assert len(persisted) == 26
