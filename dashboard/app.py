"""Painel executivo Streamlit para monitoramento e operação do SecOps Assistido."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

DEFAULT_API_BASE_URL = "http://localhost:8000"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": "#DC2626",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#22C55E",
}
DETECTOR_ORDER = ["Z-Score", "Isolation Forest", "CloudTrail Rules"]
DETECTOR_COLORS = {
    "Z-Score": "#3B82F6",
    "Isolation Forest": "#8B5CF6",
    "CloudTrail Rules": "#F59E0B",
}


def get_api_base_url() -> str:
    """Retorna a URL base da API configurada via API_BASE_URL."""
    raw = os.getenv("API_BASE_URL", DEFAULT_API_BASE_URL).strip()
    return raw.rstrip("/") if raw else DEFAULT_API_BASE_URL


@st.cache_data(ttl=10)
def fetch_health(api_base_url: str) -> Dict[str, Any]:
    """Consulta GET /health na FastAPI."""
    with httpx.Client(base_url=api_base_url, timeout=5.0) as client:
        response = client.get("/health")
        response.raise_for_status()
        return response.json()


@st.cache_data(ttl=10)
def fetch_stats(api_base_url: str) -> Dict[str, Any]:
    """Consulta GET /stats na FastAPI."""
    with httpx.Client(base_url=api_base_url, timeout=10.0) as client:
        response = client.get("/stats")
        response.raise_for_status()
        return response.json()


@st.cache_data(ttl=10)
def fetch_logs(api_base_url: str, limit: int = 500, offset: int = 0) -> Dict[str, Any]:
    """Consulta GET /logs na FastAPI."""
    with httpx.Client(base_url=api_base_url, timeout=10.0) as client:
        response = client.get("/logs", params={"limit": limit, "offset": offset})
        response.raise_for_status()
        return response.json()


def trigger_pipeline_run(
    api_base_url: str,
    regenerate_logs: bool = False,
    num_logs: int = 100,
) -> Dict[str, Any]:
    """Dispara POST /pipeline/run para processar ou regenerar logs."""
    payload = {
        "regenerate_logs": bool(regenerate_logs),
        "num_logs": int(num_logs),
    }
    with httpx.Client(base_url=api_base_url, timeout=60.0) as client:
        response = client.post("/pipeline/run", json=payload)
        response.raise_for_status()
        return response.json()


def extract_user_label(user_identity: Any) -> str:
    """Extrai um rótulo legível de usuário a partir de dict ou string."""
    if user_identity is None:
        return "Desconhecido"
    if isinstance(user_identity, dict):
        for key in ("userName", "user_name", "arn", "principalId", "accountId", "type"):
            value = user_identity.get(key)
            if value:
                return str(value)
        return "Desconhecido"
    text = str(user_identity).strip()
    return text if text else "Desconhecido"


def compute_kpis(
    stats: Optional[Dict[str, Any]],
    health: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Calcula os indicadores executivos para os cards superiores."""
    stats_data = stats or {}
    health_data = health or {}

    total_logs = int(stats_data.get("total_logs") or 0)
    total_anomalies = int(stats_data.get("total_anomalies") or 0)
    anomaly_rate = float(stats_data.get("anomaly_rate") or 0.0)

    raw_severity = stats_data.get("by_severity") or {}
    normalized_severity = {str(k).upper(): int(v or 0) for k, v in raw_severity.items()}
    critical_high_alerts = (
        normalized_severity.get("CRITICAL", 0) + normalized_severity.get("HIGH", 0)
    )

    ollama_online = str(health_data.get("ollama") or "").lower() == "online"
    ai_engine_status = "Ollama Online" if ollama_online else "Modo Fallback Jinja2"

    return {
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "anomaly_rate_pct": round(anomaly_rate * 100.0, 2),
        "critical_high_alerts": critical_high_alerts,
        "ai_engine_status": ai_engine_status,
    }


def _choose_time_freq(timestamps: pd.Series) -> str:
    """Seleciona a granularidade temporal ideal conforme a janela de logs."""
    span = timestamps.max() - timestamps.min()
    if span <= pd.Timedelta(minutes=20):
        return "1min"
    if span <= pd.Timedelta(hours=2):
        return "5min"
    if span <= pd.Timedelta(days=2):
        return "1h"
    return "1D"


def prepare_timeseries_df(logs: List[Dict[str, Any]]) -> pd.DataFrame:
    """Agrupa logs em série temporal de eventos Normais vs. Anômalos."""
    columns = ["time_bucket", "status", "count"]
    if not logs:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(logs)
    if "timestamp" not in df.columns:
        return pd.DataFrame(columns=columns)

    df = df.copy()
    df["parsed_ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["parsed_ts"])
    if df.empty:
        return pd.DataFrame(columns=columns)

    freq = _choose_time_freq(df["parsed_ts"])
    df["time_bucket"] = df["parsed_ts"].dt.floor(freq)
    is_anomaly = df["is_anomaly"].fillna(False).astype(bool) if "is_anomaly" in df else False
    df["status"] = is_anomaly.map({True: "Anômalo", False: "Normal"})

    grouped = (
        df.groupby(["time_bucket", "status"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
    )

    all_buckets = sorted(grouped["time_bucket"].unique())
    full_index = pd.MultiIndex.from_product(
        [all_buckets, ["Normal", "Anômalo"]],
        names=["time_bucket", "status"],
    )
    complete = (
        grouped.set_index(["time_bucket", "status"])
        .reindex(full_index, fill_value=0)
        .reset_index()
        .sort_values(["time_bucket", "status"])
    )
    return complete


def prepare_severity_df(stats: Optional[Dict[str, Any]]) -> pd.DataFrame:
    """Prepara distribuição de eventos por severidade em ordem semântica."""
    raw_severity = (stats or {}).get("by_severity") or {}
    normalized = {str(k).upper(): int(v or 0) for k, v in raw_severity.items()}
    rows = [{"severity": level, "count": normalized.get(level, 0)} for level in SEVERITY_ORDER]
    return pd.DataFrame(rows, columns=["severity", "count"])


def prepare_detector_df(
    stats: Optional[Dict[str, Any]],
    logs: Optional[List[Dict[str, Any]]] = None,
) -> pd.DataFrame:
    """Prepara contagem de detecções entre Z-Score, Isolation Forest e CloudTrail Rules."""
    counts = {detector: 0 for detector in DETECTOR_ORDER}

    if logs:
        for item in logs:
            if item.get("is_zscore_anomaly"):
                counts["Z-Score"] += 1
            if item.get("is_iforest_anomaly"):
                counts["Isolation Forest"] += 1
            if item.get("cloudtrail_rules_triggered"):
                counts["CloudTrail Rules"] += 1
    else:
        by_detector = (stats or {}).get("by_detector") or {}
        alias_map = {
            "statistical": "Z-Score",
            "zscore": "Z-Score",
            "z-score": "Z-Score",
            "ml": "Isolation Forest",
            "iforest": "Isolation Forest",
            "isolation_forest": "Isolation Forest",
            "isolation forest": "Isolation Forest",
            "rule": "CloudTrail Rules",
            "rules": "CloudTrail Rules",
            "cloudtrail_rules": "CloudTrail Rules",
            "cloudtrail rules": "CloudTrail Rules",
        }
        for key, value in by_detector.items():
            target = alias_map.get(str(key).strip().lower())
            if target:
                counts[target] += int(value or 0)

    rows = [{"detector": name, "count": counts[name]} for name in DETECTOR_ORDER]
    return pd.DataFrame(rows, columns=["detector", "count"])


def _top_counts(values: List[str], top_n: int) -> pd.DataFrame:
    """Conta ocorrências de rótulos não vazios e retorna Top N ordenado."""
    columns = ["name", "anomalies"]
    cleaned = [val for val in values if val]
    if not cleaned:
        return pd.DataFrame(columns=columns)
    series = pd.Series(cleaned).value_counts().head(top_n)
    return pd.DataFrame({"name": series.index.tolist(), "anomalies": series.values.tolist()})


def prepare_top_suspects(
    logs: List[Dict[str, Any]],
    top_n: int = 5,
) -> Dict[str, pd.DataFrame]:
    """Agrega Top N Eventos, IPs de Origem e Usuários com mais anomalias."""
    anomalies = [item for item in (logs or []) if item.get("is_anomaly")]
    events = [str(item.get("event_name") or "Desconhecido") for item in anomalies]
    source_ips = [str(item.get("source_ip") or "Desconhecido") for item in anomalies]
    users = [extract_user_label(item.get("user_identity")) for item in anomalies]

    return {
        "events": _top_counts(events, top_n),
        "source_ips": _top_counts(source_ips, top_n),
        "users": _top_counts(users, top_n),
    }


def _render_status_badge(label: str, is_ok: bool, ok_text: str, fail_text: str) -> None:
    """Exibe um indicador visual compacto na barra lateral."""
    if is_ok:
        st.sidebar.success(f"**{label}:** {ok_text}")
    else:
        st.sidebar.warning(f"**{label}:** {fail_text}")


def render_sidebar(
    api_base_url: str,
    health: Optional[Dict[str, Any]],
    health_error: Optional[str],
) -> None:
    """Renderiza status dos serviços e controles do pipeline na barra lateral."""
    st.sidebar.header("Status da Infraestrutura")
    st.sidebar.caption(f"API: `{api_base_url}`")

    if health_error or not health:
        st.sidebar.error("**API FastAPI:** Offline")
        st.sidebar.error("**Banco SQLite:** Indisponível")
        st.sidebar.error("**Motor IA (Ollama):** Indisponível")
    else:
        api_ok = str(health.get("status", "")).lower() == "ok"
        db_ok = str(health.get("database", "")).lower() == "connected"
        ollama_ok = str(health.get("ollama", "")).lower() == "online"

        _render_status_badge("API FastAPI", api_ok, "Online", str(health.get("status", "Erro")))
        _render_status_badge("Banco SQLite", db_ok, "Conectado", str(health.get("database", "Erro")))
        _render_status_badge(
            "Motor IA (Ollama)",
            ollama_ok,
            "Online",
            "Offline (Fallback Jinja2)",
        )

    st.sidebar.divider()
    st.sidebar.header("Operação do Pipeline")

    regenerate_logs = st.sidebar.checkbox("Regenerar logs simulados", value=False)
    num_logs = st.sidebar.slider(
        "Quantidade de logs (num_logs)",
        min_value=10,
        max_value=2000,
        value=100,
        step=10,
    )

    if st.sidebar.button("Executar Pipeline / Simular Logs", type="primary", use_container_width=True):
        try:
            with st.spinner("Executando pipeline SecOps..."):
                result = trigger_pipeline_run(
                    api_base_url=api_base_url,
                    regenerate_logs=regenerate_logs,
                    num_logs=num_logs,
                )
            processed = result.get("records_processed", 0)
            anomalies = result.get("anomalies_detected", 0)
            message = (
                f"Pipeline concluído: {processed} registros processados "
                f"e {anomalies} anomalias detectadas."
            )
            st.session_state["pipeline_success_msg"] = message
            st.toast(message)
            st.cache_data.clear()
            st.rerun()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            st.sidebar.error(f"Erro da API ({exc.response.status_code}): {detail}")
        except httpx.RequestError:
            st.sidebar.error(
                f"Não foi possível conectar à API em {api_base_url}. Verifique se o servidor está ativo."
            )
        except Exception as exc:
            st.sidebar.error(f"Falha ao executar pipeline: {exc}")


def render_kpi_cards(kpis: Dict[str, Any]) -> None:
    """Renderiza os 5 cards executivos de KPI no topo do painel."""
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total de Logs", f"{kpis['total_logs']:,}".replace(",", "."))
    col2.metric("Total de Anomalias", f"{kpis['total_anomalies']:,}".replace(",", "."))
    col3.metric("% de Anomalias", f"{kpis['anomaly_rate_pct']:.2f}%")
    col4.metric("Alertas Críticos / Altos", f"{kpis['critical_high_alerts']:,}".replace(",", "."))
    col5.metric("Status do Motor IA", kpis["ai_engine_status"])


def _render_top_suspect_bar(df: pd.DataFrame, title: str, empty_msg: str) -> None:
    """Renderiza gráfico horizontal de barras para um ranking de suspeitos."""
    if df.empty:
        st.info(empty_msg)
        return

    ordered = df.sort_values("anomalies", ascending=True)
    fig = px.bar(
        ordered,
        x="anomalies",
        y="name",
        orientation="h",
        text="anomalies",
        labels={"anomalies": "Anomalias", "name": ""},
        title=title,
        color_discrete_sequence=["#EF4444"],
    )
    fig.update_layout(
        margin=dict(l=10, r=10, t=40, b=10),
        height=300,
        yaxis=dict(automargin=True),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_charts_grid(stats: Dict[str, Any], logs: List[Dict[str, Any]]) -> None:
    """Renderiza o grid 2x2 de visualizações interativas."""
    row1_col1, row1_col2 = st.columns(2)
    row2_col1, row2_col2 = st.columns(2)

    with row1_col1:
        st.subheader("Série Temporal: Normais vs. Anômalos")
        ts_df = prepare_timeseries_df(logs)
        if ts_df.empty:
            st.info("Sem timestamps válidos nos logs para montar a série temporal.")
        else:
            fig_ts = px.line(
                ts_df,
                x="time_bucket",
                y="count",
                color="status",
                markers=True,
                color_discrete_map={"Normal": "#22C55E", "Anômalo": "#EF4444"},
                labels={"time_bucket": "Horário (UTC)", "count": "Eventos", "status": "Tipo"},
            )
            fig_ts.update_layout(
                margin=dict(l=10, r=10, t=20, b=10),
                height=340,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            )
            st.plotly_chart(fig_ts, use_container_width=True)

    with row1_col2:
        st.subheader("Distribuição por Severidade")
        sev_df = prepare_severity_df(stats)
        if sev_df["count"].sum() == 0:
            st.info("Sem dados de severidade disponíveis.")
        else:
            fig_sev = px.pie(
                sev_df,
                names="severity",
                values="count",
                hole=0.5,
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": SEVERITY_ORDER},
            )
            fig_sev.update_traces(textposition="inside", textinfo="percent+label")
            fig_sev.update_layout(margin=dict(l=10, r=10, t=20, b=10), height=340)
            st.plotly_chart(fig_sev, use_container_width=True)

    with row2_col1:
        st.subheader("Comparativo por Método de Detecção")
        det_df = prepare_detector_df(stats, logs)
        fig_det = px.bar(
            det_df,
            x="detector",
            y="count",
            color="detector",
            text="count",
            color_discrete_map=DETECTOR_COLORS,
            labels={"detector": "Método de Detecção", "count": "Detecções"},
        )
        fig_det.update_layout(
            showlegend=False,
            margin=dict(l=10, r=10, t=20, b=10),
            height=340,
        )
        st.plotly_chart(fig_det, use_container_width=True)

    with row2_col2:
        st.subheader("Top 5 Suspeitos (Anomalias)")
        suspects = prepare_top_suspects(logs, top_n=5)
        tab_events, tab_ips, tab_users = st.tabs(
            ["Top 5 Eventos", "Top 5 IPs de Origem", "Top 5 Usuários"]
        )
        with tab_events:
            _render_top_suspect_bar(
                suspects["events"],
                "Top 5 Eventos Anômalos",
                "Nenhuma anomalia registrada para ranquear eventos.",
            )
        with tab_ips:
            _render_top_suspect_bar(
                suspects["source_ips"],
                "Top 5 IPs de Origem Suspeitos",
                "Nenhuma anomalia registrada para ranquear IPs de origem.",
            )
        with tab_users:
            _render_top_suspect_bar(
                suspects["users"],
                "Top 5 Usuários Suspeitos",
                "Nenhuma anomalia registrada para ranquear usuários.",
            )


def main() -> None:
    """Ponto de entrada principal da aplicação Streamlit."""
    st.set_page_config(page_title="SecOps Assistido", layout="wide")

    st.title("SecOps Assistido — Visão Executiva")
    st.caption(
        "Monitoramento híbrido de anomalias em logs AWS CloudTrail via Z-Score, "
        "Isolation Forest, CloudTrail Rules e IA local."
    )

    api_base_url = get_api_base_url()

    health: Optional[Dict[str, Any]] = None
    health_error: Optional[str] = None
    try:
        health = fetch_health(api_base_url)
    except Exception as exc:
        health_error = str(exc)

    render_sidebar(api_base_url=api_base_url, health=health, health_error=health_error)

    if "pipeline_success_msg" in st.session_state:
        st.success(st.session_state.pop("pipeline_success_msg"))

    if health_error or health is None:
        st.error(
            f"Não foi possível conectar à API FastAPI em `{api_base_url}`. "
            "Verifique se o backend está em execução (ex.: `uvicorn api.main:app --reload`) "
            "ou ajuste a variável de ambiente `API_BASE_URL`."
        )
        return

    try:
        stats = fetch_stats(api_base_url)
        logs_payload = fetch_logs(api_base_url, limit=500, offset=0)
    except Exception as exc:
        st.error(
            f"Erro ao consultar os dados da API em `{api_base_url}`: {exc}. "
            "Verifique se a API está saudável e tente novamente."
        )
        return

    logs_items = logs_payload.get("items") or []
    kpis = compute_kpis(stats=stats, health=health)
    render_kpi_cards(kpis)

    st.divider()

    if kpis["total_logs"] == 0 and not logs_items:
        st.info(
            "Nenhum log foi processado ainda. Utilize a barra lateral para marcar "
            "**Regenerar logs simulados** (se necessário) e clique em "
            "**Executar Pipeline / Simular Logs** para iniciar a análise."
        )
        return

    render_charts_grid(stats=stats, logs=logs_items)


if __name__ == "__main__":
    main()
