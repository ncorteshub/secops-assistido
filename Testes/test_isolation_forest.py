import copy
from secops_core.detectors.isolation_forest import IsolationForestDetector


def _build_baseline_and_stealth_events():
    # 45 eventos de tráfego basal homogêneo (horário comercial, IP corporativo, eventos comuns)
    baseline = [
        {
            "event_id": f"base-{i}",
            "timestamp": f"2026-11-20T14:{i % 60:02d}:00Z",
            "source_ip": "10.0.1.15",
            "user_identity": "deploy-bot",
            "event_name": "DescribeInstances",
            "event_source": "ec2.amazonaws.com",
            "aws_region": "us-east-1",
            "bytes_transferred": 2048 + (i % 50),
            "latency_ms": 45 + (i % 10),
        }
        for i in range(45)
    ]

    # 2 eventos furtivos multivariados: horário de madrugada, região incomum, IP externo e ação rara
    anomalies = [
        {
            "event_id": "stealth-1",
            "timestamp": "2026-11-20T03:17:00Z",
            "source_ip": "185.220.101.4",
            "user_identity": "root-legacy",
            "event_name": "CreateAccessKey",
            "event_source": "iam.amazonaws.com",
            "aws_region": "ap-southeast-3",
            "bytes_transferred": 9800,
            "latency_ms": 410,
        },
        {
            "event_id": "stealth-2",
            "timestamp": "2026-11-20T03:19:00Z",
            "source_ip": "185.220.101.4",
            "user_identity": "root-legacy",
            "event_name": "StopLogging",
            "event_source": "cloudtrail.amazonaws.com",
            "aws_region": "ap-southeast-3",
            "bytes_transferred": 11200,
            "latency_ms": 390,
        },
    ]

    return baseline + anomalies


def test_isolation_forest_detects_multivariate_anomalies_and_preserves_input():
    events = _build_baseline_and_stealth_events()
    snapshot = copy.deepcopy(events)

    detector = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)
    results = detector.fit_predict(events)

    # Garante imutabilidade dos eventos originais
    assert events == snapshot
    assert len(results) == len(events)

    baseline_scores = [r["iforest_score"] for r in results[:-2]]
    anomaly_results = results[-2:]

    # Os eventos furtivos devem ser marcados como anomalia e ter score menor (mais anômalo) que a média basal
    avg_baseline_score = sum(baseline_scores) / len(baseline_scores)
    for item in anomaly_results:
        assert item["is_iforest_anomaly"] is True
        assert item["iforest_score"] < avg_baseline_score


def test_isolation_forest_reproducibility_with_fixed_random_state():
    events = _build_baseline_and_stealth_events()

    det_a = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)
    det_b = IsolationForestDetector(contamination=0.05, n_estimators=100, random_state=42)

    res_a = det_a.fit_predict(events)
    res_b = det_b.fit_predict(events)

    assert [r["iforest_score"] for r in res_a] == [r["iforest_score"] for r in res_b]
    assert [r["is_iforest_anomaly"] for r in res_a] == [r["is_iforest_anomaly"] for r in res_b]