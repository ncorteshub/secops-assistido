"""Testes da camada de API FastAPI e validação ponta a ponta com TestClient."""

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.generator import generate_logs


@pytest.fixture
def seeded_repo(repo: SecOpsRepository) -> SecOpsRepository:
    """Popula o SQLite temporário com 5 registros representativos para consulta e filtros."""
    sample_records = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-11-24T10:00:00Z",
            "source_ip": "10.0.0.10",
            "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "aws_region": "us-east-1",
            "final_severity": "LOW",
            "is_anomaly": False,
            "zscore_value": 0.2,
            "is_zscore_anomaly": False,
            "iforest_score": 0.15,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": [],
            "ai_explanation": None,
            "raw_normalized_json": {"event_id": "evt-001", "details": "normal describe"},
        },
        {
            "event_id": "evt-002",
            "timestamp": "2026-11-24T10:05:00Z",
            "source_ip": "10.0.0.20",
            "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/analyst"},
            "event_name": "GetObject",
            "event_source": "s3.amazonaws.com",
            "aws_region": "us-east-1",
            "final_severity": "MEDIUM",
            "is_anomaly": True,
            "zscore_value": 4.2,
            "is_zscore_anomaly": True,
            "iforest_score": 0.05,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": [],
            "ai_explanation": None,
            "raw_normalized_json": {"event_id": "evt-002", "details": "zscore spike"},
        },
        {
            "event_id": "evt-003",
            "timestamp": "2026-11-24T10:10:00Z",
            "source_ip": "10.0.0.30",
            "user_identity": {"type": "AssumedRole", "arn": "arn:aws:iam::123:role/DataEng"},
            "event_name": "BatchGetItem",
            "event_source": "dynamodb.amazonaws.com",
            "aws_region": "us-east-1",
            "final_severity": "HIGH",
            "is_anomaly": True,
            "zscore_value": 1.1,
            "is_zscore_anomaly": False,
            "iforest_score": -0.38,
            "is_iforest_anomaly": True,
            "cloudtrail_rules_triggered": [],
            "ai_explanation": None,
            "raw_normalized_json": {"event_id": "evt-003", "details": "ml anomaly"},
        },
        {
            "event_id": "evt-004",
            "timestamp": "2026-11-24T10:15:00Z",
            "source_ip": "198.51.100.99",
            "user_identity": {"type": "Root", "arn": "arn:aws:iam::123:root"},
            "event_name": "StopLogging",
            "event_source": "cloudtrail.amazonaws.com",
            "aws_region": "us-east-1",
            "final_severity": "CRITICAL",
            "is_anomaly": True,
            "zscore_value": 0.5,
            "is_zscore_anomaly": False,
            "iforest_score": 0.1,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": [
                {"rule_code": "RULE_TRAIL_TAMPERING", "name": "Adulteração de Trilha"}
            ],
            "ai_explanation": None,
            "raw_normalized_json": {"event_id": "evt-004", "details": "rule violation"},
        },
        {
            "event_id": "evt-005",
            "timestamp": "2026-11-24T10:20:00Z",
            "source_ip": "198.51.100.99",
            "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
            "event_name": "ConsoleLogin",
            "event_source": "signin.amazonaws.com",
            "aws_region": "us-east-1",
            "final_severity": "CRITICAL",
            "is_anomaly": True,
            "zscore_value": 5.1,
            "is_zscore_anomaly": True,
            "iforest_score": -0.42,
            "is_iforest_anomaly": True,
            "cloudtrail_rules_triggered": [
                {"rule_code": "RULE_BRUTE_FORCE", "name": "Múltiplas Falhas de Autenticação"}
            ],
            "ai_explanation": "Explicação detalhada gerada via IA para a anomalia híbrida.",
            "raw_normalized_json": {"event_id": "evt-005", "details": "hybrid anomaly"},
        },
    ]
    repo.bulk_insert(sample_records)
    return repo


class TestSecOpsReadEndpoints:
    """Valida os endpoints de consulta (/health, /stats, /logs, /anomalies/{id})."""

    def test_health_endpoint_ollama_online_and_offline(
        self, api_client: TestClient, mock_ollama_client: OllamaExplainerClient
    ):
        mock_ollama_client.healthcheck.return_value = True
        resp_on = api_client.get("/health")
        assert resp_on.status_code == 200
        assert resp_on.json() == {"status": "ok", "database": "connected", "ollama": "online"}

        mock_ollama_client.healthcheck.return_value = False
        resp_off = api_client.get("/health")
        assert resp_off.status_code == 200
        assert resp_off.json() == {"status": "ok", "database": "connected", "ollama": "offline"}

    def test_stats_endpoint_empty(
        self, api_client: TestClient, repo: SecOpsRepository
    ):
        empty_resp = api_client.get("/stats")
        assert empty_resp.status_code == 200
        empty_data = empty_resp.json()
        assert empty_data["total_logs"] == 0
        assert empty_data["total_anomalies"] == 0
        assert empty_data["anomaly_rate"] == 0.0

    def test_stats_endpoint_populated(
        self, api_client: TestClient, seeded_repo: SecOpsRepository
    ):
        response = api_client.get("/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_logs"] == 5
        assert data["total_anomalies"] == 4
        assert data["anomaly_rate"] == 0.8
        assert data["by_severity"] == {"LOW": 1, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 2}
        assert data["by_detector"]["statistical"] == 2
        assert data["by_detector"]["ml"] == 2
        assert data["by_detector"]["rule"] == 2
        assert data["by_detector"]["hybrid"] == 1
        assert data["top_source_ips"][0] == {"source_ip": "198.51.100.99", "count": 2}

    def test_logs_pagination_and_filters(
        self, api_client: TestClient, seeded_repo: SecOpsRepository
    ):
        res_all = api_client.get("/logs")
        assert res_all.status_code == 200
        assert res_all.json()["total"] == 5
        assert len(res_all.json()["items"]) == 5

        res_p1 = api_client.get("/logs?limit=2&offset=0")
        res_p2 = api_client.get("/logs?limit=2&offset=2")
        assert res_p1.status_code == 200
        assert res_p2.status_code == 200
        ids_p1 = {item["event_id"] for item in res_p1.json()["items"]}
        ids_p2 = {item["event_id"] for item in res_p2.json()["items"]}
        assert len(ids_p1) == 2 and len(ids_p2) == 2 and ids_p1.isdisjoint(ids_p2)

        assert api_client.get("/logs?is_anomaly=true").json()["total"] == 4
        assert api_client.get("/logs?is_anomaly=false").json()["items"][0]["event_id"] == "evt-001"
        assert api_client.get("/logs?severity=CRITICAL").json()["total"] == 2
        assert api_client.get("/logs?event_name=StopLogging").json()["items"][0]["event_id"] == "evt-004"
        assert api_client.get("/logs?source_ip=198.51.100.99").json()["total"] == 2
        assert api_client.get("/logs?user=root").json()["items"][0]["event_id"] == "evt-004"
        assert api_client.get("/logs?detector_type=statistical").json()["total"] == 2
        assert api_client.get("/logs?detector_type=hybrid").json()["items"][0]["event_id"] == "evt-005"

        combined = api_client.get("/logs?is_anomaly=true&severity=CRITICAL&source_ip=198.51.100.99")
        assert combined.status_code == 200
        assert combined.json()["total"] == 2

    def test_logs_validation_errors_return_422(self, api_client: TestClient):
        assert api_client.get("/logs?limit=-1").status_code == 422
        assert api_client.get("/logs?limit=501").status_code == 422
        assert api_client.get("/logs?offset=-5").status_code == 422

    def test_anomaly_detail_found_and_not_found(
        self, api_client: TestClient, seeded_repo: SecOpsRepository
    ):
        ok_resp = api_client.get("/anomalies/evt-005")
        assert ok_resp.status_code == 200
        data = ok_resp.json()
        assert data["event_id"] == "evt-005"
        assert data["final_severity"] == "CRITICAL"
        assert data["is_zscore_anomaly"] is True
        assert data["is_iforest_anomaly"] is True
        assert "raw_normalized_json" in data

        not_found = api_client.get("/anomalies/evt-nao-existe")
        assert not_found.status_code == 404


class TestSecOpsPipelineAndExplainEndpoints:
    """Valida gatilhos POST /pipeline/run, POST /anomalies/{id}/explain e fluxo ponta a ponta."""

    def test_pipeline_run_regenerate_logs_and_explanations(
        self,
        api_client: TestClient,
        repo: SecOpsRepository,
        test_logs_path: Path,
        mock_ollama_client: OllamaExplainerClient,
    ):
        with (
            patch.object(mock_ollama_client, "healthcheck", return_value=True),
            patch.object(
                mock_ollama_client,
                "_call_ollama",
                return_value="Explicação mockada via Ollama para anomalia.",
            ) as mock_call,
        ):
            response = api_client.post(
                "/pipeline/run",
                json={
                    "regenerate_logs": True,
                    "num_logs": 60,
                    "generate_explanations": True,
                    "max_explanations": 2,
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["logs_regenerated"] is True
        assert data["records_processed"] == 60
        assert data["anomalies_detected"] >= 1
        expected_explanations = min(data["anomalies_detected"], 2)
        assert data["explanations_generated"] == expected_explanations
        assert mock_call.call_count == expected_explanations
        assert test_logs_path.exists()
        assert repo.get_stats()["total_logs"] == 60

    def test_pipeline_run_without_regenerate_and_missing_file_404(
        self,
        api_client: TestClient,
        repo: SecOpsRepository,
        test_logs_path: Path,
    ):
        # Arquivo JSONL ausente com regenerate_logs=False deve retornar 404
        missing_resp = api_client.post("/pipeline/run")
        assert missing_resp.status_code == 404

        generate_logs(num_records=25, seed=7, anomaly_rate=0.2, output_file=str(test_logs_path))
        initial_content = test_logs_path.read_text(encoding="utf-8")

        response = api_client.post("/pipeline/run")
        assert response.status_code == 200
        data = response.json()
        assert data["logs_regenerated"] is False
        assert data["records_processed"] == 25
        assert data["explanations_generated"] == 0
        assert test_logs_path.read_text(encoding="utf-8") == initial_content
        assert repo.get_stats()["total_logs"] == 25

    def test_pipeline_run_validation_errors_return_422(self, api_client: TestClient):
        assert api_client.post("/pipeline/run", json={"regenerate_logs": True, "num_logs": 2001}).status_code == 422
        assert api_client.post("/pipeline/run", json={"regenerate_logs": True, "num_logs": 5}).status_code == 422
        assert api_client.post("/pipeline/run", json={"max_explanations": 51}).status_code == 422

    def test_explain_anomaly_online_fallback_and_404(
        self,
        api_client: TestClient,
        repo: SecOpsRepository,
        test_logs_path: Path,
        mock_ollama_client: OllamaExplainerClient,
    ):
        generate_logs(num_records=40, seed=42, anomaly_rate=0.2, output_file=str(test_logs_path))
        assert api_client.post("/pipeline/run", json={"regenerate_logs": False}).status_code == 200

        _, items = repo.get_logs_paginated(is_anomaly=True, limit=1, offset=0)
        assert len(items) == 1
        event_id = items[0]["event_id"]

        with (
            patch.object(mock_ollama_client, "healthcheck", return_value=True),
            patch.object(
                mock_ollama_client,
                "_call_ollama",
                return_value="Resumo executivo gerado pelo modelo local.",
            ),
        ):
            resp_ollama = api_client.post(f"/anomalies/{event_id}/explain")

        assert resp_ollama.status_code == 200
        assert resp_ollama.json() == {
            "event_id": event_id,
            "ai_explanation": "Resumo executivo gerado pelo modelo local.",
            "source": "ollama",
        }
        assert repo.get_alert_by_id(event_id)["ai_explanation"] == "Resumo executivo gerado pelo modelo local."

        with patch.object(mock_ollama_client, "healthcheck", return_value=False):
            resp_fallback = api_client.post(f"/anomalies/{event_id}/explain")

        assert resp_fallback.status_code == 200
        body_fallback = resp_fallback.json()
        assert body_fallback["source"] == "fallback"
        assert len(body_fallback["ai_explanation"]) > 0
        assert repo.get_alert_by_id(event_id)["ai_explanation"] == body_fallback["ai_explanation"]

        assert api_client.post("/anomalies/nonexistent-event-id/explain").status_code == 404

    def test_end_to_end_pipeline_logs_explain_and_detail_flow(
        self,
        api_client: TestClient,
        test_db_path: Path,
        test_logs_path: Path,
    ):
        """Fluxo ponta a ponta: POST /pipeline/run -> GET /logs -> POST /explain -> GET /anomalies/{id}."""
        # 1. Executa pipeline gerando 50 logs no diretório temporário
        run_resp = api_client.post(
            "/pipeline/run",
            json={
                "regenerate_logs": True,
                "num_logs": 50,
                "generate_explanations": False,
            },
        )
        assert run_resp.status_code == 200
        run_data = run_resp.json()
        assert run_data["records_processed"] == 50
        assert run_data["anomalies_detected"] >= 1
        assert test_logs_path.exists()
        assert test_db_path.exists()

        # 2. Lista anomalias via GET /logs
        logs_resp = api_client.get("/logs?is_anomaly=true&limit=10")
        assert logs_resp.status_code == 200
        logs_data = logs_resp.json()
        assert logs_data["total"] == run_data["anomalies_detected"]
        target_event_id = logs_data["items"][0]["event_id"]

        # 3. Gera explicação via POST /anomalies/{event_id}/explain (fallback determinístico ativo por padrão)
        explain_resp = api_client.post(f"/anomalies/{target_event_id}/explain")
        assert explain_resp.status_code == 200
        explain_data = explain_resp.json()
        assert explain_data["event_id"] == target_event_id
        assert explain_data["source"] == "fallback"
        assert len(explain_data["ai_explanation"]) > 0

        # 4. Consulta detalhe completo via GET /anomalies/{event_id} e confirma persistência
        detail_resp = api_client.get(f"/anomalies/{target_event_id}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["event_id"] == target_event_id
        assert detail_data["is_anomaly"] is True
        assert detail_data["ai_explanation"] == explain_data["ai_explanation"]

        # Garante que nenhum secops.db foi criado na raiz do repositório
        assert not Path("secops.db").exists()
