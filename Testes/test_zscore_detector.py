import copy
from secops_core.detectors.zscore_detector import ZScoreDetector


def test_zscore_normal_distribution_no_anomalies():
    detector = ZScoreDetector(threshold=3.0)
    # Série estável sem outliers extremos
    normal_series = [10, 11, 9, 10, 12, 10, 9, 11, 10, 10]
    results = detector.detect_series(normal_series)

    assert len(results) == len(normal_series)
    assert all(not item["is_zscore_anomaly"] for item in results)


def test_zscore_extreme_spike_detection_and_immutability():
    detector = ZScoreDetector(threshold=3.0)

    # 20 eventos normais de usuários distintos + 1 pico extremo de exfiltração (bytes_transferred)
    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": f"2026-11-20T18:{i:02d}:00Z",
            "source_ip": f"10.0.0.{i + 1}",
            "user_identity": f"user-{i}",
            "bytes_transferred": 1024,
        }
        for i in range(20)
    ]
    events.append(
        {
            "event_id": "evt-exfil",
            "timestamp": "2026-11-20T18:25:00Z",
            "source_ip": "10.0.0.99",
            "user_identity": "compromised-user",
            "bytes_transferred": 50_000_000,  # Pico extremo
        }
    )

    original_snapshot = copy.deepcopy(events)
    enriched = detector.detect(events)

    # Garante que os eventos originais NÃO foram alterados
    assert events == original_snapshot

    # O último evento deve ser sinalizado como anomalia com Z-Score > 3.0
    assert enriched[-1]["event_id"] == "evt-exfil"
    assert enriched[-1]["is_zscore_anomaly"] is True
    assert enriched[-1]["zscore_value"] > 3.0

    # Os eventos normais permanecem sem anomalia
    assert all(item["is_zscore_anomaly"] is False for item in enriched[:-1])


def test_zscore_zero_standard_deviation_protection():
    detector = ZScoreDetector(threshold=3.0)
    # Todos os valores idênticos -> sigma = 0 (não pode lançar ZeroDivisionError)
    constant_events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": f"2026-11-20T18:{i:02d}:00Z",
            "source_ip": "192.168.1.10",
            "user_identity": "service-account",
            "bytes_transferred": 500,
        }
        for i in range(5)
    ]

    enriched = detector.detect(constant_events)
    assert all(item["zscore_value"] == 0.0 for item in enriched)
    assert all(item["is_zscore_anomaly"] is False for item in enriched)


def test_zscore_configurable_threshold_via_env(monkeypatch):
    monkeypatch.setenv("SECOPS_ZSCORE_THRESHOLD", "1.5")
    detector = ZScoreDetector()
    assert detector.threshold == 1.5

    series = [10, 10, 10, 10, 25]
    results = detector.detect_series(series)
    assert results[-1]["is_zscore_anomaly"] is True