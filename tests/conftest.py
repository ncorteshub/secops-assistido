"""Fixtures compartilhadas e isolamento total de banco/logs/LLM para a suíte MAO-23."""

from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_logs_path, get_ollama_client, get_repository
from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Retorna o caminho de um banco SQLite temporário isolado do secops.db principal."""
    return tmp_path / "test_secops.db"


@pytest.fixture
def test_logs_path(tmp_path: Path) -> Path:
    """Retorna o caminho de um arquivo JSONL temporário isolado em tmp_path."""
    return tmp_path / "test_logs.jsonl"


@pytest.fixture(autouse=True)
def isolate_environment_paths(
    monkeypatch: pytest.MonkeyPatch,
    test_db_path: Path,
    test_logs_path: Path,
) -> None:
    """Garante por padrão que variáveis de ambiente não apontem para o banco ou logs principais."""
    monkeypatch.setenv("SECOPS_DB_PATH", str(test_db_path))
    monkeypatch.setenv("SECOPS_LOGS_PATH", str(test_logs_path))


@pytest.fixture
def repo(test_db_path: Path) -> SecOpsRepository:
    """Instancia um SecOpsRepository apontando exclusivamente para o SQLite temporário."""
    return SecOpsRepository(db_path=test_db_path)


@pytest.fixture
def mock_ollama_client(monkeypatch: pytest.MonkeyPatch) -> OllamaExplainerClient:
    """
    Fornece um OllamaExplainerClient com chamadas HTTP mockadas por padrão.

    Mantém o renderizador Jinja2 real ativo (permitindo validar o fallback
    determinístico) sem depender de um servidor Ollama em execução.
    """
    client = OllamaExplainerClient(base_url="http://localhost:11434", model="llama3.2")
    monkeypatch.setattr(client, "healthcheck", MagicMock(return_value=False))
    monkeypatch.setattr(client, "_call_ollama", MagicMock(return_value=None))
    return client


@pytest.fixture
def api_client(
    repo: SecOpsRepository,
    test_logs_path: Path,
    mock_ollama_client: OllamaExplainerClient,
) -> Generator[TestClient, None, None]:
    """
    Cliente HTTP TestClient da FastAPI com dependency_overrides para banco,
    caminho de logs JSONL e cliente Ollama mockado.
    """
    app.dependency_overrides[get_repository] = lambda: repo
    app.dependency_overrides[get_logs_path] = lambda: str(test_logs_path)
    app.dependency_overrides[get_ollama_client] = lambda: mock_ollama_client
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()
