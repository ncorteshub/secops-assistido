import os
import time
from pathlib import Path
from typing import Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from api.schemas import (
    AnomalyDetailResponse,
    ExplainResponse,
    HealthResponse,
    LogsListResponse,
    PipelineRunRequest,
    PipelineRunResponse,
    StatsResponse,
)
from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.generator import generate_logs
from secops_core.pipeline import HybridSecOpsPipeline


def get_repository() -> SecOpsRepository:
    """Provedor injetável da camada de persistência SQLite."""
    db_path = os.getenv("SECOPS_DB_PATH", "data/secops.db")
    return SecOpsRepository(db_path=db_path)


def get_ollama_client() -> OllamaExplainerClient:
    """Provedor injetável do cliente Ollama local."""
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    return OllamaExplainerClient(base_url=base_url, model=model)


def get_logs_path() -> str:
    """Provedor injetável do caminho para o arquivo JSONL de logs simulados."""
    return os.getenv("SECOPS_LOGS_PATH", "data/logs_simulados.jsonl")


app = FastAPI(
    title="SecOps Assistido API",
    description=(
        "API REST de alta performance para consulta de logs, detecção de anomalias, "
        "métricas executivas e explicações IA locais para o projeto secops-assistido."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Verificação de integridade da API e dependências",
    tags=["Health"],
)
def health_check(
    repo: SecOpsRepository = Depends(get_repository),
    ollama_client: OllamaExplainerClient = Depends(get_ollama_client),
) -> HealthResponse:
    """Verifica e retorna a saúde da API, conexão com o SQLite e servidor Ollama local."""
    # Verificação do banco SQLite
    try:
        with repo._get_connection() as conn:
            conn.execute("SELECT 1;").fetchone()
        db_status = "connected"
    except Exception:
        db_status = "error"

    # Verificação do servidor Ollama local
    ollama_online = ollama_client.healthcheck()
    ollama_status = "online" if ollama_online else "offline"

    return HealthResponse(
        status="ok",
        database=db_status,
        ollama=ollama_status,
    )


@app.get(
    "/stats",
    response_model=StatsResponse,
    summary="Resumo executivo e métricas de segurança",
    tags=["Dashboard"],
)
def get_stats(
    repo: SecOpsRepository = Depends(get_repository),
) -> StatsResponse:
    """Retorna métricas executivas consolidadas: totais, taxa de anomalias, agrupamentos e rankings."""
    stats = repo.get_stats()
    return StatsResponse(**stats)


@app.get(
    "/logs",
    response_model=LogsListResponse,
    summary="Listagem paginada e filtrada de logs",
    tags=["Logs"],
)
def get_logs(
    is_anomaly: Optional[bool] = Query(
        default=None,
        description="Filtrar por anomalias confirmadas (True) ou eventos normais (False)",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filtrar por severidade (LOW, MEDIUM, HIGH, CRITICAL)",
    ),
    event_name: Optional[str] = Query(
        default=None,
        description="Filtrar por nome exato do evento CloudTrail",
    ),
    user: Optional[str] = Query(
        default=None,
        description="Filtrar por usuário ou ARN da identidade (busca parcial)",
    ),
    source_ip: Optional[str] = Query(
        default=None,
        description="Filtrar por endereço IP de origem",
    ),
    detector_type: Optional[str] = Query(
        default=None,
        description="Filtrar por detector: statistical, ml, rule, hybrid",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Quantidade de registros por página (1 a 500)",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Deslocamento da paginação",
    ),
    repo: SecOpsRepository = Depends(get_repository),
) -> LogsListResponse:
    """Retorna listagem paginada de logs processados com filtros combináveis e seguros."""
    total, items = repo.get_logs_paginated(
        is_anomaly=is_anomaly,
        severity=severity,
        event_name=event_name,
        user=user,
        source_ip=source_ip,
        detector_type=detector_type,
        limit=limit,
        offset=offset,
    )
    return LogsListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=items,
    )


@app.get(
    "/anomalies/{event_id}",
    response_model=AnomalyDetailResponse,
    summary="Consulta de detalhes completos de um alerta de segurança",
    tags=["Anomalies"],
)
def get_anomaly_detail(
    event_id: str,
    repo: SecOpsRepository = Depends(get_repository),
) -> AnomalyDetailResponse:
    """Busca um alerta específico pelo event_id, incluindo métricas completas e ai_explanation."""
    alert = repo.get_alert_by_id(event_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alerta ou evento com ID '{event_id}' não encontrado.",
        )
    return AnomalyDetailResponse(**alert)


def _resolve_explanation_source(ollama_client: OllamaExplainerClient) -> str:
    """Determina a origem da explicação ('ollama' ou 'fallback') após a geração."""
    last_source = getattr(ollama_client, "last_source", None)
    if last_source in {"ollama", "fallback"}:
        return last_source
    return "ollama" if ollama_client.healthcheck() else "fallback"


@app.post(
    "/pipeline/run",
    response_model=PipelineRunResponse,
    summary="Executa o pipeline completo de detecção sob demanda",
    tags=["Pipeline"],
)
def run_pipeline(
    request: PipelineRunRequest = Body(default_factory=PipelineRunRequest),
    repo: SecOpsRepository = Depends(get_repository),
    ollama_client: OllamaExplainerClient = Depends(get_ollama_client),
    logs_path: str = Depends(get_logs_path),
) -> PipelineRunResponse:
    """Regenera logs (opcional), executa o pipeline híbrido, persiste no SQLite e gera explicações opcionais."""
    start_time = time.perf_counter()

    if request.regenerate_logs:
        Path(logs_path).parent.mkdir(parents=True, exist_ok=True)
        generate_logs(num_records=request.num_logs, output_file=logs_path)

    pipeline = HybridSecOpsPipeline(db_path=str(repo.db_path), repository=repo)
    try:
        results = pipeline.run_from_jsonl(logs_path, persist=True)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    anomalies = [result for result in results if result.is_anomaly]
    explanations_generated = 0

    if request.generate_explanations and anomalies:
        for anomaly in anomalies[: request.max_explanations]:
            explanation = ollama_client.generate_explanation(
                data=anomaly,
                event_id=anomaly.event_id,
                persist=False,
            )
            repo.update_ai_explanation(anomaly.event_id, explanation)
            explanations_generated += 1

    elapsed = round(time.perf_counter() - start_time, 4)
    return PipelineRunResponse(
        status="ok",
        logs_regenerated=request.regenerate_logs,
        records_processed=len(results),
        anomalies_detected=len(anomalies),
        explanations_generated=explanations_generated,
        execution_time_seconds=elapsed,
    )


@app.post(
    "/anomalies/{event_id}/explain",
    response_model=ExplainResponse,
    summary="Gera ou regenera a explicação IA para um alerta específico",
    tags=["Anomalies"],
)
def explain_anomaly(
    event_id: str,
    repo: SecOpsRepository = Depends(get_repository),
    ollama_client: OllamaExplainerClient = Depends(get_ollama_client),
) -> ExplainResponse:
    """Gera explicação via Ollama (ou fallback Jinja2), persiste em ai_explanation e retorna o resultado."""
    alert = repo.get_alert_by_id(event_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alerta ou evento com ID '{event_id}' não encontrado.",
        )

    alert_context = dict(alert)
    raw_json = alert_context.get("raw_normalized_json")
    if isinstance(raw_json, dict) and not alert_context.get("technical_justification"):
        justification = raw_json.get("technical_justification") or raw_json.get("anomaly_reason")
        if justification:
            alert_context["technical_justification"] = justification

    explanation = ollama_client.generate_explanation(
        data=alert_context,
        event_id=event_id,
        persist=False,
    )
    repo.update_ai_explanation(event_id, explanation)
    source = _resolve_explanation_source(ollama_client)

    return ExplainResponse(
        event_id=event_id,
        ai_explanation=explanation,
        source=source,
    )
