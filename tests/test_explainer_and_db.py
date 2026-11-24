"""Testes da camada de Explicabilidade (Jinja2 + Ollama) e Persistência SQLite."""

import json
import sqlite3
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from jinja2.exceptions import UndefinedError

from secops_core.db import SecOpsRepository
from secops_core.detectors.cloudtrail_rules import RuleViolation, Severity
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.explainer.renderer import (
    AlertExplanationContext,
    AlertExplanationRenderer,
    render_alert_explanation,
    render_fallback_explanation,
)
from secops_core.pipeline import DetectionResult

MANDATORY_SECTIONS = [
    "1) O que aconteceu (Resumo Simples)",
    "2) Por que foi considerado anômalo",
    "3) Risco Potencial",
    "4) Ação Recomendada",
]


class MockHTTPResponse:
    """Mock para emular respostas HTTP do urllib.request.urlopen."""

    def __init__(self, data: dict, status: int = 200) -> None:
        self.status = status
        self._data = json.dumps(data).encode("utf-8")

    def read(self) -> bytes:
        return self._data

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def _assert_mandatory_sections_and_clean_tokens(text: str, *, require_prompt_directives: bool) -> None:
    """Valida presença das 4 seções obrigatórias e ausência de tokens Jinja2 não renderizados."""
    for section in MANDATORY_SECTIONS:
        assert section in text, f"Seção obrigatória ausente: {section}"

    for token in ("{{", "}}", "{%", "%}"):
        assert token not in text, f"Token Jinja2 não renderizado encontrado: {token}"

    if require_prompt_directives:
        assert "ANTI-ALUCINAÇÃO" in text
        assert "português do Brasil" in text


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    return DetectionResult(
        event_id="evt-ollama-001",
        timestamp="2026-11-24T20:00:00Z",
        event_source="cloudtrail.amazonaws.com",
        event_name="StopLogging",
        is_anomaly=True,
        severity=Severity.CRITICAL,
        triggered_detectors=["CLOUDTRAIL_RULES", "Z_SCORE"],
        rule_violations=[
            RuleViolation(
                rule_code="RULE_TRAIL_TAMPERING",
                name="Adulteração de Trilha",
                severity=Severity.CRITICAL,
                technical_reason="Chamada StopLogging detectada.",
            )
        ],
        zscore_anomaly=True,
        zscore_value=4.5,
        isolation_forest_anomaly=False,
        isolation_forest_score=0.1,
        technical_justification="Adulteração crítica de auditoria combinada com pico estatístico.",
        raw_event={
            "event_id": "evt-ollama-001",
            "source_ip": "198.51.100.99",
            "user_identity": {"arn": "arn:aws:iam::123456789012:user/admin"},
        },
    )


class TestJinjaTemplatesRenderer:
    """Valida renderização dos templates alert_explanation.j2 e fallback_explanation.j2."""

    @pytest.fixture
    def renderer(self) -> AlertExplanationRenderer:
        return AlertExplanationRenderer()

    def test_alert_template_statistical_only(self, renderer: AlertExplanationRenderer):
        prompt = renderer.render(
            user="arn:aws:iam::123456789012:user/analyst",
            source_ip="198.51.100.24",
            event_name="GetObject",
            event_source="s3.amazonaws.com",
            timestamp="2026-11-24T14:30:00Z",
            severity="MEDIUM",
            zscore=4.82,
            iforest_score=None,
            cloudtrail_rules=None,
        )

        _assert_mandatory_sections_and_clean_tokens(prompt, require_prompt_directives=True)
        assert "Desvio Estatístico (Z-Score): 4.82" in prompt
        assert "Isolation Forest" not in prompt
        assert "Regras Determinísticas CloudTrail Violadas" not in prompt

    def test_alert_template_ml_isolation_forest_only(self, renderer: AlertExplanationRenderer):
        context = AlertExplanationContext(
            user="arn:aws:iam::123456789012:role/DataPipelineRole",
            source_ip="203.0.113.88",
            event_name="BatchGetItem",
            event_source="dynamodb.amazonaws.com",
            timestamp="2026-11-24T03:15:00Z",
            severity="HIGH",
            zscore=None,
            iforest_score=-0.2854,
            cloudtrail_rules=None,
        )

        prompt = renderer.render(context)
        _assert_mandatory_sections_and_clean_tokens(prompt, require_prompt_directives=True)
        assert "Score de Machine Learning (Isolation Forest): -0.2854" in prompt
        assert "Z-Score" not in prompt
        assert "Regras Determinísticas CloudTrail Violadas" not in prompt

    def test_alert_template_rule_only(self, renderer: AlertExplanationRenderer):
        rules = [
            RuleViolation(
                rule_code="RULE_ROOT_ACTIVITY",
                name="Uso da Conta Root AWS",
                severity=Severity.HIGH,
                technical_reason="Ação administrativa executada diretamente com as credenciais root.",
            ),
            RuleViolation(
                rule_code="RULE_TRAIL_TAMPERING",
                name="Adulteração ou Desativação de CloudTrail",
                severity=Severity.CRITICAL,
                technical_reason="Tentativa de execução de StopLogging na trilha principal.",
            ),
        ]

        prompt = renderer.render(
            user="arn:aws:iam::123456789012:root",
            source_ip="192.0.2.1",
            event_name="StopLogging",
            event_source="cloudtrail.amazonaws.com",
            timestamp="2026-11-24T22:00:00Z",
            severity="CRITICAL",
            zscore=None,
            iforest_score=None,
            cloudtrail_rules=rules,
        )

        _assert_mandatory_sections_and_clean_tokens(prompt, require_prompt_directives=True)
        assert "[RULE_ROOT_ACTIVITY] Uso da Conta Root AWS" in prompt
        assert "[RULE_TRAIL_TAMPERING] Adulteração ou Desativação de CloudTrail" in prompt
        assert "Z-Score" not in prompt
        assert "Isolation Forest" not in prompt

    def test_alert_template_hybrid_anomaly(self):
        rules = [
            {
                "rule_code": "RULE_EXCESSIVE_FAILURES",
                "name": "Múltiplas Falhas de Autenticação",
                "severity": "HIGH",
                "technical_reason": "Mais de 10 tentativas com falha seguidas por sucesso.",
            }
        ]

        prompt = render_alert_explanation(
            user="arn:aws:iam::123456789012:user/compromised_dev",
            source_ip="185.220.101.5",
            event_name="ConsoleLogin",
            event_source="signin.amazonaws.com",
            timestamp="2026-11-24T23:45:00Z",
            severity="CRITICAL",
            zscore=5.12,
            iforest_score=-0.412,
            cloudtrail_rules=rules,
            technical_justification="Regras determinísticas violadas com desvio estatístico e ML.",
        )

        _assert_mandatory_sections_and_clean_tokens(prompt, require_prompt_directives=True)
        assert "Desvio Estatístico (Z-Score): 5.12" in prompt
        assert "Score de Machine Learning (Isolation Forest): -0.412" in prompt
        assert "[RULE_EXCESSIVE_FAILURES] Múltiplas Falhas de Autenticação" in prompt
        assert "Justificativa Técnica Consolidada" in prompt

    def test_fallback_template_renders_all_metric_combinations(
        self, renderer: AlertExplanationRenderer, sample_detection_result: DetectionResult
    ):
        # Combinação híbrida via DetectionResult
        fallback_hybrid = renderer.render_fallback(sample_detection_result)
        _assert_mandatory_sections_and_clean_tokens(fallback_hybrid, require_prompt_directives=False)
        assert "StopLogging" in fallback_hybrid
        assert "4.5" in fallback_hybrid
        assert "RULE_TRAIL_TAMPERING" in fallback_hybrid

        # Apenas ML (Isolation Forest) via função auxiliar
        fallback_ml = render_fallback_explanation(
            user="arn:aws:iam::123456789012:role/AppRole",
            source_ip="203.0.113.50",
            event_name="AssumeRole",
            event_source="sts.amazonaws.com",
            timestamp="2026-11-24T04:00:00Z",
            severity="HIGH",
            zscore=None,
            iforest_score=-0.35,
            cloudtrail_rules=None,
        )
        _assert_mandatory_sections_and_clean_tokens(fallback_ml, require_prompt_directives=False)
        assert "-0.35" in fallback_ml
        assert "AssumeRole" in fallback_ml

    def test_strict_undefined_raises_on_unknown_variable(self, renderer: AlertExplanationRenderer):
        template_with_unknown = renderer.env.from_string("Olá {{ unknown_unprovided_var }}")
        with pytest.raises(UndefinedError):
            template_with_unknown.render()


class TestOllamaExplainerClient:
    """Valida cliente Ollama online (mockado) e acionamento automático de fallback."""

    def test_healthcheck_online_and_offline(self):
        client = OllamaExplainerClient()
        with patch("urllib.request.urlopen", return_value=MockHTTPResponse({"models": []}, status=200)):
            assert client.healthcheck() is True

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            assert client.healthcheck() is False

    def test_ollama_online_generation_success(self, sample_detection_result: DetectionResult):
        mock_ai_response = (
            "### 1) O que aconteceu (Resumo Simples)\n"
            "Execução de StopLogging.\n\n"
            "### 2) Por que foi considerado anômalo\n"
            "Violação RULE_TRAIL_TAMPERING e Z-Score 4.5.\n\n"
            "### 3) Risco Potencial\n"
            "Cegueira de auditoria.\n\n"
            "### 4) Ação Recomendada\n"
            "Reativar trilha CloudTrail."
        )

        client = OllamaExplainerClient(model="llama3.2")

        def fake_urlopen(req, timeout=None):
            if req.get_method() == "GET":
                return MockHTTPResponse({"models": []}, status=200)
            return MockHTTPResponse({"response": mock_ai_response}, status=200)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            explanation = client.generate_explanation(sample_detection_result)

        assert explanation == mock_ai_response
        assert client.last_source == "ollama"

    def test_ollama_offline_triggers_deterministic_fallback(
        self, sample_detection_result: DetectionResult
    ):
        client = OllamaExplainerClient()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            explanation = client.generate_explanation(sample_detection_result)

        assert client.last_source == "fallback"
        _assert_mandatory_sections_and_clean_tokens(explanation, require_prompt_directives=False)
        assert "StopLogging" in explanation
        assert "198.51.100.99" in explanation
        assert "RULE_TRAIL_TAMPERING" in explanation

    def test_ollama_timeout_triggers_deterministic_fallback(
        self, sample_detection_result: DetectionResult
    ):
        client = OllamaExplainerClient()

        def fake_urlopen(req, timeout=None):
            if req.get_method() == "GET":
                return MockHTTPResponse({"models": []}, status=200)
            raise TimeoutError("Tempo limite de inferência excedido")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            explanation = client.generate_explanation(sample_detection_result)

        assert client.last_source == "fallback"
        _assert_mandatory_sections_and_clean_tokens(explanation, require_prompt_directives=False)


class TestSQLitePersistence:
    """Valida persistência em lote, idempotência, atualização de ai_explanation e migração."""

    def test_bulk_insert_performance_and_idempotency(self, repo: SecOpsRepository):
        now = datetime.now(timezone.utc).isoformat()
        sample_records = [
            {
                "event_id": f"evt-{i}",
                "timestamp": now,
                "source_ip": "192.168.1.50",
                "user_identity": "admin-role",
                "event_name": "ConsoleLogin" if i % 10 != 0 else "DeleteTrail",
                "event_source": "cloudtrail.amazonaws.com",
                "aws_region": "us-east-1",
                "zscore_value": 3.4 if i % 10 == 0 else 0.2,
                "is_zscore_anomaly": (i % 10 == 0),
                "iforest_score": -0.75 if i % 10 == 0 else 0.15,
                "is_iforest_anomaly": (i % 10 == 0),
                "cloudtrail_rules_triggered": ["CT-001"] if i % 10 == 0 else [],
                "final_severity": "HIGH" if i % 10 == 0 else "LOW",
                "is_anomaly": (i % 10 == 0),
            }
            for i in range(5000)
        ]

        start = time.perf_counter()
        inserted = repo.bulk_insert(sample_records)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert inserted == 5000
        assert elapsed_ms < 500.0, f"Inserção demorou {elapsed_ms:.2f}ms"
        assert repo.bulk_insert(sample_records) == 0

        assert repo.update_ai_explanation("evt-0", "Tentativa suspeita de desativar CloudTrail.") is True
        assert repo.update_ai_explanation("evt-inexistente", "Sem efeito") is False

        anomalies = repo.query_alerts(only_anomalies=True, severity="HIGH", limit=10)
        assert len(anomalies) == 10
        assert anomalies[0]["cloudtrail_rules_triggered"] == ["CT-001"]

    def test_explainer_persists_ai_explanation_in_temp_sqlite(
        self, repo: SecOpsRepository, sample_detection_result: DetectionResult
    ):
        inserted = repo.bulk_insert([sample_detection_result.to_db_record()])
        assert inserted == 1

        alert_before = repo.get_alert_by_id(sample_detection_result.event_id)
        assert alert_before is not None
        assert alert_before["ai_explanation"] is None

        client = OllamaExplainerClient(repository=repo)
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Ollama down")):
            explanation = client.generate_explanation(sample_detection_result, persist=True)

        alert_after = repo.get_alert_by_id(sample_detection_result.event_id)
        assert alert_after is not None
        assert alert_after["ai_explanation"] == explanation
        assert "StopLogging" in alert_after["ai_explanation"]

    def test_sqlite_schema_migration_adds_ai_explanation(self, tmp_path: Path):
        db_file = tmp_path / "legacy.db"
        conn = sqlite3.connect(db_file)
        conn.execute(
            """
            CREATE TABLE security_alerts (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                user_identity TEXT,
                event_name TEXT,
                event_source TEXT,
                aws_region TEXT,
                raw_normalized_json TEXT NOT NULL,
                final_severity TEXT NOT NULL DEFAULT 'LOW',
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                processed_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()

        migrated_repo = SecOpsRepository(db_path=db_file)
        with migrated_repo._get_connection() as c:
            cols = [row["name"] for row in c.execute("PRAGMA table_info(security_alerts);").fetchall()]
            assert "ai_explanation" in cols
