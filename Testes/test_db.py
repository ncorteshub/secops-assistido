import time
from datetime import datetime, timezone
from pathlib import Path
from secops_core.db import SecOpsRepository


def test_db_bulk_insert_performance_and_idempotency(tmp_path: Path):
    db_file = tmp_path / "test_secops.db"
    repo = SecOpsRepository(db_path=db_file)

    now = datetime.now(timezone.utc).isoformat()
    sample_records = [
        {
            "event_id": f"evt-{i}",
            "timestamp": now,
            "source_ip": "192.168.1.50",
            "user_identity": "admin-role",
            "event_name": "ConsoleLogin" if i % 10 != 0 else "DeleteTrail",
            "event_source": "cloudtrail.amazonaws.com",
            "aws_region": "us-east-1",
            "zscore_value": 3.4 if i % 10 == 0 else 0.2,
            "is_zscore_anomaly": (i % 10 == 0),
            "iforest_score": -0.75 if i % 10 == 0 else 0.15,
            "is_iforest_anomaly": (i % 10 == 0),
            "cloudtrail_rules_triggered": ["CT-001"] if i % 10 == 0 else [],
            "final_severity": "HIGH" if i % 10 == 0 else "LOW",
            "is_anomaly": (i % 10 == 0),
        }
        for i in range(5000)
    ]

    # 1. Teste de performance para 5.000 registros
    start = time.perf_counter()
    inserted = repo.bulk_insert(sample_records)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert inserted == 5000
    assert elapsed_ms < 100.0, f"Inserção demorou {elapsed_ms:.2f}ms (limite: 100ms)"

    # 2. Teste de idempotência (reprocessar os mesmos 5.000 eventos)
    inserted_again = repo.bulk_insert(sample_records)
    assert inserted_again == 0

    # 3. Teste de atualização da IA e leitura filtrada
    assert repo.update_ai_explanation("evt-0", "Tentativa suspeita de desativar CloudTrail.")
    anomalies = repo.query_alerts(only_anomalies=True, severity="HIGH", limit=10)
    assert len(anomalies) == 10
    assert anomalies[0]["cloudtrail_rules_triggered"] == ["CT-001"]