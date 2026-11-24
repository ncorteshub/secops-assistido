from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Contrato de resposta para verificação de saúde da API, SQLite e Ollama."""

    status: str = Field(default="ok", description="Status operacional da API ('ok')")
    database: str = Field(description="Status da conexão com o banco SQLite ('connected' ou 'error')")
    ollama: str = Field(description="Status de conectividade com o servidor Ollama local ('online' ou 'offline')")


class TopEventItem(BaseModel):
    """Item do ranking de eventos mais frequentes/suspeitos."""

    event_name: str = Field(description="Nome do evento ou API CloudTrail registrada")
    count: int = Field(description="Quantidade total de ocorrências registradas")


class TopSourceIpItem(BaseModel):
    """Item do ranking de IPs mais frequentes/suspeitos."""

    source_ip: str = Field(description="Endereço IP de origem")
    count: int = Field(description="Quantidade total de ocorrências registradas")


class StatsResponse(BaseModel):
    """Resumo executivo consolidado com métricas do pipeline SecOps."""

    total_logs: int = Field(..., description="Total de logs processados e armazenados no banco")
    total_anomalies: int = Field(..., description="Total de anomalias detectadas pelo pipeline")
    anomaly_rate: float = Field(..., description="Taxa de anomalias (proporção de 0.0 a 1.0; 0.0 se sem logs)")
    by_severity: Dict[str, int] = Field(
        default_factory=dict,
        description="Contagem de logs agrupados por severidade (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    by_detector: Dict[str, int] = Field(
        default_factory=dict,
        description="Contagem de anomalias por tipo de detector (statistical/zscore, ml/iforest, rule/cloudtrail_rules, hybrid)",
    )
    top_events: List[TopEventItem] = Field(
        default_factory=list,
        description="Ranking dos eventos CloudTrail mais recorrentes",
    )
    top_source_ips: List[TopSourceIpItem] = Field(
        default_factory=list,
        description="Ranking dos IPs de origem mais recorrentes",
    )


class LogItem(BaseModel):
    """Representação de um log/alerta de segurança processado."""

    event_id: str = Field(..., description="Identificador único do evento")
    timestamp: str = Field(..., description="Data/hora do registro no formato ISO-8601")
    source_ip: Optional[str] = Field(default=None, description="Endereço IP de origem")
    user_identity: Optional[Union[Dict[str, Any], str]] = Field(
        default=None, description="Identidade IAM / ARN associada ao evento"
    )
    event_name: Optional[str] = Field(default=None, description="Nome da ação registrada")
    event_source: Optional[str] = Field(default=None, description="Serviço AWS de origem")
    aws_region: Optional[str] = Field(default=None, description="Região da AWS")
    final_severity: str = Field(..., description="Nível de severidade consolidado pelo pipeline")
    is_anomaly: bool = Field(..., description="Indica se o evento é uma anomalia confirmada")
    zscore_value: Optional[float] = Field(default=0.0, description="Métrica estatística calculada pelo Z-Score")
    is_zscore_anomaly: bool = Field(default=False, description="Disparo do detector estatístico Z-Score")
    iforest_score: Optional[float] = Field(default=0.0, description="Score comportamental do Isolation Forest")
    is_iforest_anomaly: bool = Field(
        default=False, description="Disparo do detector de Machine Learning Isolation Forest"
    )
    cloudtrail_rules_triggered: List[Any] = Field(
        default_factory=list, description="Lista de violações de regras determinísticas disparadas"
    )
    ai_explanation: Optional[str] = Field(
        default=None, description="Explicação contextualizada gerada pela IA local ou fallback determinístico"
    )
    processed_at: Optional[str] = Field(default=None, description="Timestamp de processamento no pipeline")


class LogsListResponse(BaseModel):
    """Contrato de resposta paginada para a listagem de logs."""

    total: int = Field(..., description="Total de logs correspondentes aos filtros aplicados")
    limit: int = Field(..., description="Limite máximo de registros retornados na página atual")
    offset: int = Field(..., description="Deslocamento da paginação")
    items: List[LogItem] = Field(default_factory=list, description="Lista de registros de logs")


class AnomalyDetailResponse(LogItem):
    """Detalhes completos de um alerta específico, incluindo payload bruto normalizado."""

    raw_normalized_json: Optional[Union[Dict[str, Any], str]] = Field(
        default=None, description="Payload completo e normalizado do evento no padrão canônico LGMS"
    )
