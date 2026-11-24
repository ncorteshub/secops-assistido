import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from api.schemas import (
    AnomalyDetailResponse,
    HealthResponse,
    LogsListResponse,
    StatsResponse,
)
from secops_core.db import SecOpsRepository
from secops_core.explainer.ollama_client import OllamaExplainerClient


def get_repository() -> SecOpsRepository:
    """Provedor injetável da camada de persistência SQLite."""
    db_path = os.getenv("SECOPS_DB_PATH", "data/secops.db")
    return SecOpsRepository(db_path=db_path)


def get_ollama_client() -> OllamaExplainerClient:
    """Provedor injetável do cliente Ollama local."""
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    return OllamaExplainerClient(base_url=base_url, model=model)


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
