import json
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_ollama_client, get_repository
from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_api_secops.db"


@pytest.fixture
def repo(test_db_path: Path) -> SecOpsRepository:
    repository = SecOpsRepository(db_path=test_db_path)

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

    repository.bulk_insert(sample_records)
    return repository


@pytest.fixture
def mock_ollama_client() -> OllamaExplainerClient:
    client = MagicMock(spec=OllamaExplainerClient)
    client.healthcheck.return_value = True
    return client


@pytest.fixture
def client(repo: SecOpsRepository, mock_ollama_client: OllamaExplainerClient) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_repository] = lambda: repo
    app.dependency_overrides[get_ollama_client] = lambda: mock_ollama_client
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestSecOpsAPI:
    """Suíte de testes para os endpoints REST FastAPI da Task MAO-18."""

    def test_health_endpoint_ollama_online(self, client: TestClient, mock_ollama_client: MagicMock):
        mock_ollama_client.healthcheck.return_value = True
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"
        assert data["ollama"] == "online"

    def test_health_endpoint_ollama_offline(self, client: TestClient, mock_ollama_client: MagicMock):
        mock_ollama_client.healthcheck.return_value = False
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"
        assert data["ollama"] == "offline"

    def test_stats_endpoint(self, client: TestClient):
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_logs"] == 5
        assert data["total_anomalies"] == 4
        assert data["anomaly_rate"] == 0.8

        # Agrupamento por severidade
        assert data["by_severity"]["LOW"] == 1
        assert data["by_severity"]["MEDIUM"] == 1
        assert data["by_severity"]["HIGH"] == 1
        assert data["by_severity"]["CRITICAL"] == 2

        # Agrupamento por detector
        assert data["by_detector"]["statistical"] == 2
        assert data["by_detector"]["ml"] == 2
        assert data["by_detector"]["rule"] == 2
        assert data["by_detector"]["hybrid"] == 1

        # Rankings
        assert len(data["top_events"]) > 0
        assert len(data["top_source_ips"]) > 0
        # O IP 198.51.100.99 possui 2 registros e deve liderar o ranking de IPs
        assert data["top_source_ips"][0]["source_ip"] == "198.51.100.99"
        assert data["top_source_ips"][0]["count"] == 2

    def test_logs_without_filters(self, client: TestClient):
        response = client.get("/logs")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 5
        assert data["limit"] == 50
        assert data["offset"] == 0
        assert len(data["items"]) == 5

    def test_logs_pagination(self, client: TestClient):
        # Página 1 (limit=2, offset=0)
        res1 = client.get("/logs?limit=2&offset=0")
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["total"] == 5
        assert len(data1["items"]) == 2

        # Página 2 (limit=2, offset=2)
        res2 = client.get("/logs?limit=2&offset=2")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["total"] == 5
        assert len(data2["items"]) == 2

        # Garante que os registros retornados são distintos
        ids_p1 = {item["event_id"] for item in data1["items"]}
        ids_p2 = {item["event_id"] for item in data2["items"]}
        assert ids_p1.isdisjoint(ids_p2)

    def test_logs_filters_individual(self, client: TestClient):
        # Filtro is_anomaly=true
        res_anom = client.get("/logs?is_anomaly=true")
        assert res_anom.status_code == 200
        assert res_anom.json()["total"] == 4

        # Filtro is_anomaly=false
        res_norm = client.get("/logs?is_anomaly=false")
        assert res_norm.status_code == 200
        assert res_norm.json()["total"] == 1
        assert res_norm.json()["items"][0]["event_id"] == "evt-001"

        # Filtro severity=CRITICAL
        res_sev = client.get("/logs?severity=CRITICAL")
        assert res_sev.status_code == 200
        assert res_sev.json()["total"] == 2

        # Filtro event_name=StopLogging
        res_ev = client.get("/logs?event_name=StopLogging")
        assert res_ev.status_code == 200
        assert res_ev.json()["total"] == 1
        assert res_ev.json()["items"][0]["event_id"] == "evt-004"

        # Filtro source_ip=198.51.100.99
        res_ip = client.get("/logs?source_ip=198.51.100.99")
        assert res_ip.status_code == 200
        assert res_ip.json()["total"] == 2

        # Filtro user (parcial: "root")
        res_user = client.get("/logs?user=root")
        assert res_user.status_code == 200
        assert res_user.json()["total"] == 1
        assert res_user.json()["items"][0]["event_id"] == "evt-004"

        # Filtro detector_type=statistical
        res_stat = client.get("/logs?detector_type=statistical")
        assert res_stat.status_code == 200
        assert res_stat.json()["total"] == 2

        # Filtro detector_type=hybrid
        res_hyb = client.get("/logs?detector_type=hybrid")
        assert res_hyb.status_code == 200
        assert res_hyb.json()["total"] == 1
        assert res_hyb.json()["items"][0]["event_id"] == "evt-005"

    def test_logs_filters_combined(self, client: TestClient):
        # Combinação: is_anomaly=true + severity=CRITICAL + source_ip=198.51.100.99
        response = client.get("/logs?is_anomaly=true&severity=CRITICAL&source_ip=198.51.100.99")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["is_anomaly"] is True
            assert item["final_severity"] == "CRITICAL"
            assert item["source_ip"] == "198.51.100.99"

    def test_logs_validation_error(self, client: TestClient):
        # limit negativo deve retornar 422
        res1 = client.get("/logs?limit=-1")
        assert res1.status_code == 422

        # limit maior que o permitido (500) deve retornar 422
        res2 = client.get("/logs?limit=501")
        assert res2.status_code == 422

        # offset negativo deve retornar 422
        res3 = client.get("/logs?offset=-5")
        assert res3.status_code == 422

    def test_anomaly_detail_found(self, client: TestClient):
        response = client.get("/anomalies/evt-005")
        assert response.status_code == 200
        data = response.json()
        assert data["event_id"] == "evt-005"
        assert data["event_name"] == "ConsoleLogin"
        assert data["final_severity"] == "CRITICAL"
        assert data["is_anomaly"] is True
        assert data["is_zscore_anomaly"] is True
        assert data["zscore_value"] == 5.1
        assert data["is_iforest_anomaly"] is True
        assert data["iforest_score"] == -0.42
        assert len(data["cloudtrail_rules_triggered"]) == 1
        assert "RULE_BRUTE_FORCE" in str(data["cloudtrail_rules_triggered"])
        assert data["ai_explanation"] == "Explicação detalhada gerada via IA para a anomalia híbrida."
        assert "raw_normalized_json" in data

    def test_anomaly_detail_not_found(self, client: TestClient):
        response = client.get("/anomalies/evt-nao-existe")
        assert response.status_code == 404
        assert "não encontrado" in response.json()["detail"]
