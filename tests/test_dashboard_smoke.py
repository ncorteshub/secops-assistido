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
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, path, **kwargs):
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
                return FakeResponse(
                    {
                        "total": 2,
                        "limit": 500,
                        "offset": 0,
                        "items": [
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
                        ],
                    }
                )
            raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(httpx, "Client", OnlineClient)
    dashboard_app.fetch_health.clear()
    dashboard_app.fetch_stats.clear()
    dashboard_app.fetch_logs.clear()

    at_online = AppTest.from_file(APP_PATH).run()
    assert not at_online.exception
    assert len(at_online.metric) == 5
