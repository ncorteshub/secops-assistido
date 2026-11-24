from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_logs_path, get_ollama_client, get_repository
from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.generator import generate_logs


@pytest.fixture()
def api_context(tmp_path: Path):
    """Configura banco SQLite temporário, caminho de logs isolado e cliente Ollama mockado."""
    db_path = tmp_path / "test_secops.db"
    logs_path = tmp_path / "logs_simulados.jsonl"
    repo = SecOpsRepository(db_path=db_path)

    ollama_client = OllamaExplainerClient(base_url="http://localhost:11434", model="llama3.2")

    app.dependency_overrides[get_repository] = lambda: repo
    app.dependency_overrides[get_logs_path] = lambda: str(logs_path)
    app.dependency_overrides[get_ollama_client] = lambda: ollama_client

    with TestClient(app) as client:
        yield {
            "client": client,
            "repo": repo,
            "db_path": db_path,
            "logs_path": logs_path,
            "ollama_client": ollama_client,
        }

    app.dependency_overrides.clear()


def test_pipeline_run_with_regenerate_logs_true_and_explanations(api_context):
    """Valida POST /pipeline/run com regenerate_logs=True, gravação no SQLite e limite max_explanations."""
    client: TestClient = api_context["client"]
    repo: SecOpsRepository = api_context["repo"]
    logs_path: Path = api_context["logs_path"]
    ollama_client: OllamaExplainerClient = api_context["ollama_client"]

    with (
        patch.object(ollama_client, "healthcheck", return_value=True),
        patch.object(
            ollama_client,
            "_call_ollama",
            return_value="Explicação mockada via Ollama para anomalia.",
        ) as mock_call,
    ):
        response = client.post(
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
    assert isinstance(data["execution_time_seconds"], float)
    assert data["execution_time_seconds"] >= 0.0

    assert logs_path.exists()
    stats = repo.get_stats()
    assert stats["total_logs"] == 60
    assert stats["total_anomalies"] == data["anomalies_detected"]


def test_pipeline_run_with_regenerate_logs_false_and_empty_body(api_context):
    """Valida POST /pipeline/run com body vazio (defaults: regenerate_logs=False) e persistência no SQLite."""
    client: TestClient = api_context["client"]
    repo: SecOpsRepository = api_context["repo"]
    logs_path: Path = api_context["logs_path"]

    generate_logs(num_records=25, seed=7, anomaly_rate=0.2, output_file=str(logs_path))
    initial_content = logs_path.read_text(encoding="utf-8")

    response = client.post("/pipeline/run")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert data["logs_regenerated"] is False
    assert data["records_processed"] == 25
    assert data["explanations_generated"] == 0
    assert logs_path.read_text(encoding="utf-8") == initial_content

    stats = repo.get_stats()
    assert stats["total_logs"] == 25


def test_pipeline_run_rejects_excessive_batch_size(api_context):
    """Valida erro 422 ao enviar num_logs acima do limite máximo (2000)."""
    client: TestClient = api_context["client"]

    response = client.post(
        "/pipeline/run",
        json={
            "regenerate_logs": True,
            "num_logs": 2001,
        },
    )

    assert response.status_code == 422


def test_explain_anomaly_updates_sqlite_and_handles_missing_event(api_context):
    """Valida POST /anomalies/{event_id}/explain (200 com Ollama e fallback, persistência no SQLite e 404)."""
    client: TestClient = api_context["client"]
    repo: SecOpsRepository = api_context["repo"]
    logs_path: Path = api_context["logs_path"]
    ollama_client: OllamaExplainerClient = api_context["ollama_client"]

    generate_logs(num_records=40, seed=42, anomaly_rate=0.2, output_file=str(logs_path))
    run_resp = client.post("/pipeline/run", json={"regenerate_logs": False})
    assert run_resp.status_code == 200

    _, items = repo.get_logs_paginated(is_anomaly=True, limit=1, offset=0)
    assert len(items) == 1
    event_id = items[0]["event_id"]

    # Cenário 1: Ollama online (mockado)
    with (
        patch.object(ollama_client, "healthcheck", return_value=True),
        patch.object(
            ollama_client,
            "_call_ollama",
            return_value="Resumo executivo gerado pelo modelo local.",
        ),
    ):
        resp_ollama = client.post(f"/anomalies/{event_id}/explain")

    assert resp_ollama.status_code == 200
    body_ollama = resp_ollama.json()
    assert body_ollama == {
        "event_id": event_id,
        "ai_explanation": "Resumo executivo gerado pelo modelo local.",
        "source": "ollama",
    }

    updated_alert = repo.get_alert_by_id(event_id)
    assert updated_alert is not None
    assert updated_alert["ai_explanation"] == "Resumo executivo gerado pelo modelo local."

    # Cenário 2: Ollama offline -> fallback Jinja2 automático e atualização no SQLite
    with patch.object(ollama_client, "healthcheck", return_value=False):
        resp_fallback = client.post(f"/anomalies/{event_id}/explain")

    assert resp_fallback.status_code == 200
    body_fallback = resp_fallback.json()
    assert body_fallback["event_id"] == event_id
    assert body_fallback["source"] == "fallback"
    assert len(body_fallback["ai_explanation"]) > 0

    reupdated_alert = repo.get_alert_by_id(event_id)
    assert reupdated_alert is not None
    assert reupdated_alert["ai_explanation"] == body_fallback["ai_explanation"]

    # Cenário 3: event_id inexistente -> 404
    resp_not_found = client.post("/anomalies/nonexistent-event-id/explain")
    assert resp_not_found.status_code == 404
