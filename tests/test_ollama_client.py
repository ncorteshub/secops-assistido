import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secops_core.db import SecOpsRepository
from secops_core.detectors.cloudtrail_rules import RuleViolation, Severity
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.pipeline import DetectionResult


MANDATORY_TOPICS = [
    "1) O que aconteceu (Resumo Simples)",
    "2) Por que foi considerado anômalo",
    "3) Risco Potencial",
    "4) Ação Recomendada",
]


class MockHTTPResponse:
    """Mock para emular respostas do urllib.request.urlopen."""

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


@pytest.fixture
def mock_detection_result() -> DetectionResult:
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


class TestOllamaClient:
    """Testes unitários para Task MAO-17 (Ollama client, fallback Jinja2 e persistência SQLite)."""

    def test_healthcheck_online(self):
        """Valida que healthcheck retorna True quando o servidor Ollama responde 200."""
        client = OllamaExplainerClient()
        with patch("urllib.request.urlopen", return_value=MockHTTPResponse({"models": []}, status=200)):
            assert client.healthcheck() is True

    def test_healthcheck_offline(self):
        """Valida que healthcheck retorna False quando o servidor está inacessível."""
        client = OllamaExplainerClient()
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            assert client.healthcheck() is False

    def test_ollama_online_generation_success(self, mock_detection_result):
        """Cenário 1: Ollama Online (com mock) retorna explicação do modelo."""
        mock_ai_response = (
            "### 1) O que aconteceu (Resumo Simples)\n"
            "A conta de administração executou o evento StopLogging no serviço CloudTrail.\n\n"
            "### 2) Por que foi considerado anômalo\n"
            "Foi detectada a violação da regra RULE_TRAIL_TAMPERING e desvio estatístico de Z-Score 4.5.\n\n"
            "### 3) Risco Potencial\n"
            "Cegueira operacional de auditoria e encobrimento de ações maliciosas.\n\n"
            "### 4) Ação Recomendada\n"
            "Reativar a trilha imediatamente e revogar credenciais do usuário admin."
        )

        client = OllamaExplainerClient(model="llama3.2")

        def fake_urlopen(req, timeout=None):
            # Se for healthcheck GET /api/tags
            if req.get_method() == "GET":
                return MockHTTPResponse({"models": []}, status=200)
            # Se for POST /api/generate
            return MockHTTPResponse({"response": mock_ai_response}, status=200)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            explanation = client.generate_explanation(mock_detection_result)

        assert explanation == mock_ai_response
        assert "StopLogging" in explanation
        assert "RULE_TRAIL_TAMPERING" in explanation

    def test_ollama_offline_fallback_trigger(self, mock_detection_result):
        """Cenário 2: Ollama Offline aciona automaticamente o fallback Jinja2 sem levantar exceções."""
        client = OllamaExplainerClient()

        # Simula Ollama offline no healthcheck
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            explanation = client.generate_explanation(mock_detection_result)

        # Valida que não explodiu exceção e retornou a explicação de fallback
        assert isinstance(explanation, str)
        assert len(explanation) > 0

        # Valida os 4 tópicos obrigatórios na explicação de fallback
        for topic in MANDATORY_TOPICS:
            assert topic in explanation, f"Tópico ausente na explicação de fallback: {topic}"

        # Valida injeção correta dos dados no fallback
        assert "StopLogging" in explanation
        assert "cloudtrail.amazonaws.com" in explanation
        assert "198.51.100.99" in explanation
        assert "arn:aws:iam::123456789012:user/admin" in explanation
        assert "CRITICAL" in explanation
        assert "4.5" in explanation
        assert "RULE_TRAIL_TAMPERING" in explanation

    def test_ollama_timeout_fallback_trigger(self, mock_detection_result):
        """Cenário 2 (variação): Ollama passa no healthcheck mas dá timeout em /api/generate."""
        client = OllamaExplainerClient()

        def fake_urlopen(req, timeout=None):
            if req.get_method() == "GET":
                return MockHTTPResponse({"models": []}, status=200)
            # POST dá Timeout
            raise TimeoutError("Tempo limite de inferência excedido (30s)")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            explanation = client.generate_explanation(mock_detection_result)

        # Fallback deve ser acionado transparentemente
        assert isinstance(explanation, str)
        for topic in MANDATORY_TOPICS:
            assert topic in explanation

    def test_sqlite_persistence_flow(self, tmp_path: Path, mock_detection_result):
        """Cenário 3: Valida persistência da coluna ai_explanation no banco SQLite."""
        db_file = tmp_path / "secops_test_persistence.db"
        repo = SecOpsRepository(db_path=db_file)

        # Insere o alerta inicialmente sem ai_explanation
        record = mock_detection_result.to_db_record()
        inserted_count = repo.bulk_insert([record])
        assert inserted_count == 1

        alert_before = repo.get_alert_by_id(mock_detection_result.event_id)
        assert alert_before is not None
        assert alert_before["ai_explanation"] is None

        # Executa o cliente com fallback e persistência ativa
        client = OllamaExplainerClient(repository=repo)
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Ollama down")):
            explanation = client.generate_explanation(mock_detection_result, persist=True)

        # Valida que o registro no banco agora possui a explicação salva
        alert_after = repo.get_alert_by_id(mock_detection_result.event_id)
        assert alert_after is not None
        assert alert_after["ai_explanation"] == explanation
        assert "StopLogging" in alert_after["ai_explanation"]

    def test_sqlite_schema_migration_if_column_missing(self, tmp_path: Path):
        """Valida que init_db adiciona ai_explanation caso a tabela tenha sido criada em schema antigo."""
        import sqlite3

        db_file = tmp_path / "legacy.db"
        conn = sqlite3.connect(db_file)
        # Cria tabela antiga SEM ai_explanation
        conn.execute("""
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
        """)
        conn.commit()
        conn.close()

        # Inicializa o repositório no banco legado
        repo = SecOpsRepository(db_path=db_file)

        # Verifica se a migração adicionou a coluna ai_explanation
        with repo._get_connection() as c:
            cols = [row["name"] for row in c.execute("PRAGMA table_info(security_alerts);").fetchall()]
            assert "ai_explanation" in cols
