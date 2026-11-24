"""Testes smoke para o painel executivo Streamlit em dashboard/app.py."""

import importlib
from pathlib import Path

import httpx
from streamlit.testing.v1 import AppTest

from dashboard import app as dashboard_app

APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def test_dashboard_import_and_config_helpers(monkeypatch):
    """Valida importação limpa do módulo e leitura de API_BASE_URL."""
    reloaded = importlib.reload(dashboard_app)
    assert hasattr(reloaded, "main")

    monkeypatch.delenv("API_BASE_URL", raising=False)
    assert reloaded.get_api_base_url() == "http://localhost:8000"

    monkeypatch.setenv("API_BASE_URL", "http://127.0.0.1:9000/")
    assert reloaded.get_api_base_url() == "http://127.0.0.1:9000"


def test_compute_kpis_contract():
    """Valida cálculo dos 5 KPIs a partir dos contratos de /stats e /health."""
    stats = {
        "total_logs": 100,
        "total_anomalies": 12,
        "anomaly_rate": 0.1234,
        "by_severity": {"CRITICAL": 3, "HIGH": 4, "MEDIUM": 10, "LOW": 83},
        "by_detector": {"statistical": 2, "ml": 3, "rule": 4, "hybrid": 3},
        "top_events": [],
        "top_source_ips": [],
    }
    health_online = {"status": "ok", "database": "connected", "ollama": "online"}
    kpis = dashboard_app.compute_kpis(stats=stats, health=health_online)

    assert kpis["total_logs"] == 100
    assert kpis["total_anomalies"] == 12
    assert kpis["anomaly_rate_pct"] == 12.34
    assert kpis["critical_high_alerts"] == 7
    assert kpis["ai_engine_status"] == "Ollama Online"

    health_offline = {"status": "ok", "database": "connected", "ollama": "offline"}
    kpis_fallback = dashboard_app.compute_kpis(stats=stats, health=health_offline)
    assert kpis_fallback["ai_engine_status"] == "Modo Fallback Jinja2"


def test_prepare_charts_aggregations_and_empty_state():
    """Valida agregações de série temporal, severidade, detectores e top 5 suspeitos."""
    # Estado vazio
    assert dashboard_app.prepare_timeseries_df([]).empty
    empty_suspects = dashboard_app.prepare_top_suspects([])
    assert empty_suspects["events"].empty
    assert empty_suspects["source_ips"].empty
    assert empty_suspects["users"].empty

    sample_logs = [
        {
            "event_id": "1",
            "timestamp": "2026-11-24T10:00:00Z",
            "source_ip": "10.0.0.1",
            "user_identity": {"userName": "alice"},
            "event_name": "ConsoleLogin",
            "final_severity": "LOW",
            "is_anomaly": False,
            "is_zscore_anomaly": False,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": [],
        },
        {
            "event_id": "2",
            "timestamp": "2026-11-24T10:05:00Z",
            "source_ip": "198.51.100.7",
            "user_identity": {"userName": "mallory"},
            "event_name": "DeleteTrail",
            "final_severity": "CRITICAL",
            "is_anomaly": True,
            "is_zscore_anomaly": True,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": ["cloudtrail_stop_delete"],
        },
        {
            "event_id": "3",
            "timestamp": "2026-11-24T10:10:00Z",
            "source_ip": "198.51.100.7",
            "user_identity": "arn:aws:iam::123456789012:user/mallory",
            "event_name": "CreateUser",
            "final_severity": "HIGH",
            "is_anomaly": True,
            "is_zscore_anomaly": False,
            "is_iforest_anomaly": True,
            "cloudtrail_rules_triggered": [],
        },
    ]

    ts_df = dashboard_app.prepare_timeseries_df(sample_logs)
    assert list(ts_df.columns) == ["time_bucket", "status", "count"]
    assert int(ts_df.loc[ts_df["status"] == "Normal", "count"].sum()) == 1
    assert int(ts_df.loc[ts_df["status"] == "Anômalo", "count"].sum()) == 2

    sev_df = dashboard_app.prepare_severity_df(
        {"by_severity": {"CRITICAL": 1, "HIGH": 1, "LOW": 1}}
    )
    assert list(sev_df["severity"]) == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert list(sev_df["count"]) == [1, 1, 0, 1]

    det_from_logs = dashboard_app.prepare_detector_df(stats={}, logs=sample_logs)
    assert dict(zip(det_from_logs["detector"], det_from_logs["count"])) == {
        "Z-Score": 1,
        "Isolation Forest": 1,
        "CloudTrail Rules": 1,
    }

    det_from_stats = dashboard_app.prepare_detector_df(
        stats={"by_detector": {"statistical": 4, "ml": 2, "rule": 5}},
        logs=[],
    )
    assert dict(zip(det_from_stats["detector"], det_from_stats["count"])) == {
        "Z-Score": 4,
        "Isolation Forest": 2,
        "CloudTrail Rules": 5,
    }

    suspects = dashboard_app.prepare_top_suspects(sample_logs, top_n=5)
    assert suspects["source_ips"].iloc[0].to_dict() == {
        "name": "198.51.100.7",
        "anomalies": 2,
    }
    assert set(suspects["events"]["name"]) == {"DeleteTrail", "CreateUser"}
    assert set(suspects["users"]["name"]) == {
        "mallory",
        "arn:aws:iam::123456789012:user/mallory",
    }


def test_streamlit_app_renders_online_and_offline(monkeypatch):
    """Valida renderização completa via AppTest nos cenários offline e online."""
    # Cenário 1: API offline deve exibir st.error amigável sem exception
    class OfflineClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "Client", OfflineClient)
    dashboard_app.fetch_health.clear()
    at_offline = AppTest.from_file(APP_PATH).run()
    assert not at_offline.exception
    assert len(at_offline.error) >= 1

    # Cenário 2: API online com dados válidos deve renderizar KPIs e gráficos 2x2
    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class OnlineClient:
        def __init__(self, *args, **kwargs):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, path, **kwargs):
            params = kwargs.get("params") or {}
            if path == "/health":
                return FakeResponse(
                    {"status": "ok", "database": "connected", "ollama": "offline"}
                )
            if path == "/stats":
                return FakeResponse(
                    {
                        "total_logs": 2,
                        "total_anomalies": 1,
                        "anomaly_rate": 0.5,
                        "by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1},
                        "by_detector": {"rule": 1},
                        "top_events": [{"event_name": "DeleteTrail", "count": 1}],
                        "top_source_ips": [{"source_ip": "198.51.100.7", "count": 1}],
                    }
                )
            if path == "/logs":
                items = [
                    {
                        "event_id": "1",
                        "timestamp": "2026-11-24T10:00:00Z",
                        "source_ip": "10.0.0.1",
                        "user_identity": {"userName": "alice"},
                        "event_name": "ConsoleLogin",
                        "final_severity": "LOW",
                        "is_anomaly": False,
                        "is_zscore_anomaly": False,
                        "is_iforest_anomaly": False,
                        "cloudtrail_rules_triggered": [],
                    },
                    {
                        "event_id": "2",
                        "timestamp": "2026-11-24T10:05:00Z",
                        "source_ip": "198.51.100.7",
                        "user_identity": {"userName": "mallory"},
                        "event_name": "DeleteTrail",
                        "final_severity": "CRITICAL",
                        "is_anomaly": True,
                        "is_zscore_anomaly": True,
                        "is_iforest_anomaly": False,
                        "cloudtrail_rules_triggered": ["cloudtrail_stop_delete"],
                        "ai_explanation": None,
                    },
                ]
                if params.get("is_anomaly") is True:
                    anomalies = [item for item in items if item["is_anomaly"]]
                    return FakeResponse(
                        {
                            "total": len(anomalies),
                            "limit": params.get("limit", 200),
                            "offset": params.get("offset", 0),
                            "items": anomalies,
                        }
                    )
                return FakeResponse(
                    {
                        "total": 2,
                        "limit": 500,
                        "offset": 0,
                        "items": items,
                    }
                )
            if path == "/anomalies/2":
                return FakeResponse(
                    {
                        "event_id": "2",
                        "timestamp": "2026-11-24T10:05:00Z",
                        "source_ip": "198.51.100.7",
                        "user_identity": {"userName": "mallory"},
                        "event_name": "DeleteTrail",
                        "event_source": "cloudtrail.amazonaws.com",
                        "aws_region": "us-east-1",
                        "final_severity": "CRITICAL",
                        "is_anomaly": True,
                        "zscore_value": 4.25,
                        "is_zscore_anomaly": True,
                        "iforest_score": -0.18,
                        "is_iforest_anomaly": False,
                        "cloudtrail_rules_triggered": ["cloudtrail_stop_delete"],
                        "ai_explanation": "Alerta crítico de exclusão de trilha CloudTrail.",
                        "raw_normalized_json": {
                            "event_id": "2",
                            "event_name": "DeleteTrail",
                            "source_ip": "198.51.100.7",
                        },
                    }
                )
            raise AssertionError(f"Unexpected path: {path}")

        def post(self, path, **kwargs):
            if path == "/anomalies/2/explain":
                return FakeResponse(
                    {
                        "event_id": "2",
                        "ai_explanation": "Nova explicação gerada via fallback.",
                        "source": "fallback",
                    }
                )
            raise AssertionError(f"Unexpected POST path: {path}")

    monkeypatch.setattr(httpx, "Client", OnlineClient)
    dashboard_app.fetch_health.clear()
    dashboard_app.fetch_stats.clear()
    dashboard_app.fetch_logs.clear()
    dashboard_app.fetch_filtered_anomalies.clear()
    dashboard_app.fetch_anomaly_detail.clear()

    at_online = AppTest.from_file(APP_PATH).run()
    assert not at_online.exception
    tab_labels = [tab.label for tab in at_online.tabs]
    assert "Visão Executiva" in tab_labels
    assert "Investigação de Alertas & IA" in tab_labels
    # 5 KPIs na aba executiva + 3 métricas de scores na aba de investigação
    assert len(at_online.metric) == 8

    # Aciona botão de regeneração de explicação IA na aba de investigação
    explain_buttons = [
        btn for btn in at_online.button if btn.label == "Regenerar Explicação com IA"
    ]
    assert len(explain_buttons) == 1
    explain_buttons[0].click().run()
    assert not at_online.exception
    assert any("Fallback Jinja2" in msg.value for msg in at_online.success)


def test_investigation_filter_params_and_table_helpers():
    """Valida construção de filtros da API, formatação de tabela e sanitização LGMS."""
    params_all = dashboard_app.build_anomaly_filter_params(
        severity="Todas",
        detector_label="Todos",
        event_name="",
        user_or_ip="",
    )
    assert params_all == {"is_anomaly": True, "limit": 200, "offset": 0}

    params_ip = dashboard_app.build_anomaly_filter_params(
        severity="critical",
        detector_label="Z-Score",
        event_name=" DeleteTrail ",
        user_or_ip=" 198.51.100.7 ",
    )
    assert params_ip == {
        "is_anomaly": True,
        "limit": 200,
        "offset": 0,
        "severity": "CRITICAL",
        "detector_type": "statistical",
        "event_name": "DeleteTrail",
        "source_ip": "198.51.100.7",
    }

    params_user_ml = dashboard_app.build_anomaly_filter_params(
        severity="HIGH",
        detector_label="Isolation Forest",
        user_or_ip="mallory",
    )
    assert params_user_ml["detector_type"] == "ml"
    assert params_user_ml["user"] == "mallory"
    assert "source_ip" not in params_user_ml

    params_rules = dashboard_app.build_anomaly_filter_params(
        detector_label="CloudTrail Rules",
    )
    assert params_rules["detector_type"] == "rule"

    sample = [
        {
            "event_id": "evt-99",
            "timestamp": "2026-11-24T12:00:00Z",
            "final_severity": "CRITICAL",
            "event_name": "DeleteTrail",
            "user_identity": {"userName": "mallory"},
            "source_ip": "198.51.100.7",
            "is_zscore_anomaly": True,
            "is_iforest_anomaly": False,
            "cloudtrail_rules_triggered": ["cloudtrail_stop_delete"],
            "ai_explanation": "**Resumo:** Exclusão suspeita de trilha.",
        }
    ]
    assert dashboard_app.format_anomaly_option(sample[0]) == (
        "[CRITICAL] DeleteTrail — mallory (evt-99)"
    )
    df = dashboard_app.prepare_anomalies_table_df(sample)
    assert list(df.columns) == [
        "Horário (UTC)",
        "Severidade",
        "Evento",
        "Usuário",
        "IP de Origem",
        "Detector",
        "Explicação IA",
    ]
    assert df.iloc[0]["Detector"] == "Z-Score, CloudTrail Rules"
    assert df.iloc[0]["Explicação IA"].startswith("Gerada — Resumo:")
    assert dashboard_app.prepare_anomalies_table_df([]).empty

    sanitized = dashboard_app.sanitize_payload_for_display(
        '{"event_id": "evt-99", "db_path": "data/secops.db", '
        '"local_file": "C:\\\\Users\\\\admin\\\\secret.txt", '
        '"access_key": "AKIA123", "nested": {"unix_path": "/home/user/.env"}}'
    )
    assert sanitized["event_id"] == "evt-99"
    assert sanitized["db_path"] == "[REDACTED]"
    assert sanitized["access_key"] == "[REDACTED]"
    assert sanitized["local_file"] == "[PATH_REDACTED]"
    assert sanitized["nested"]["unix_path"] == "[PATH_REDACTED]"


def test_investigation_api_client_helpers(monkeypatch):
    """Valida chamadas HTTP para GET /logs filtrado, GET /anomalies/{id} e POST /explain."""
    recorded_calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class MockHttpClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, path, **kwargs):
            recorded_calls.append(("GET", path, kwargs.get("params")))
            if path == "/logs":
                return FakeResponse({"total": 1, "limit": 200, "offset": 0, "items": [{"event_id": "evt-1"}]})
            if path == "/anomalies/evt-1":
                return FakeResponse({"event_id": "evt-1", "final_severity": "HIGH", "zscore_value": 3.5})
            raise AssertionError(f"Unexpected GET path: {path}")

        def post(self, path, **kwargs):
            recorded_calls.append(("POST", path, kwargs.get("json")))
            if path == "/anomalies/evt-1/explain":
                return FakeResponse(
                    {"event_id": "evt-1", "ai_explanation": "Explicação Ollama.", "source": "ollama"}
                )
            raise AssertionError(f"Unexpected POST path: {path}")

    monkeypatch.setattr(httpx, "Client", MockHttpClient)
    dashboard_app.fetch_filtered_anomalies.clear()
    dashboard_app.fetch_anomaly_detail.clear()

    filtered = dashboard_app.fetch_filtered_anomalies(
        api_base_url="http://localhost:8000",
        severity="HIGH",
        detector_label="CloudTrail Rules",
        event_name="CreateUser",
        user_or_ip="alice",
    )
    assert filtered["total"] == 1
    assert recorded_calls[0] == (
        "GET",
        "/logs",
        {
            "is_anomaly": True,
            "limit": 200,
            "offset": 0,
            "severity": "HIGH",
            "detector_type": "rule",
            "event_name": "CreateUser",
            "user": "alice",
        },
    )

    detail = dashboard_app.fetch_anomaly_detail(
        api_base_url="http://localhost:8000",
        event_id="evt-1",
    )
    assert detail["event_id"] == "evt-1"
    assert detail["zscore_value"] == 3.5
    assert recorded_calls[1] == ("GET", "/anomalies/evt-1", None)

    explained = dashboard_app.trigger_anomaly_explanation(
        api_base_url="http://localhost:8000",
        event_id="evt-1",
    )
    assert explained["source"] == "ollama"
    assert explained["ai_explanation"] == "Explicação Ollama."
    assert recorded_calls[2] == ("POST", "/anomalies/evt-1/explain", None)
