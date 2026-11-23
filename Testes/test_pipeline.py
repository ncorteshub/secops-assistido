import json
from pathlib import Path
from secops_core.detectors.cloudtrail_rules import Severity
from secops_core.pipeline import HybridSecOpsPipeline


def test_pipeline_end_to_end_jsonl_to_sqlite(tmp_path: Path):
    jsonl_file = tmp_path / "logs_simulados.jsonl"
    db_file = tmp_path / "secops_test.db"

    sample_logs = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-11-22T20:00:00Z",
            "event_source": "ec2.amazonaws.com",
            "event_name": "DescribeInstances",
            "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
            "source_ip": "10.0.0.10",
            "aws_region": "us-east-1",
            "status": "Success",
            "request_count": 1,
            "bytes_transferred": 512,
        },
        {
            "event_id": "evt-002",
            "timestamp": "2026-11-22T20:01:00Z",
            "event_source": "cloudtrail.amazonaws.com",
            "event_name": "StopLogging",
            "user_identity": {"type": "Root", "arn": "arn:aws:iam::123:root"},
            "source_ip": "203.0.113.99",
            "aws_region": "us-east-1",
            "status": "Success",
            "request_count": 1,
            "bytes_transferred": 256,
        },
        {
            "event_id": "evt-003",
            "timestamp": "2026-11-22T20:02:00Z",
            "event_source": "s3.amazonaws.com",
            "event_name": "GetObject",
            "user_identity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/analyst"},
            "source_ip": "10.0.0.25",
            "aws_region": "us-east-1",
            "status": "Success",
            "request_count": 150,
            "bytes_transferred": 950000,
        },
    ]

    with jsonl_file.open("w", encoding="utf-8") as f:
        for log in sample_logs:
            f.write(json.dumps(log) + "\n")

    mock_zscore = lambda evs: [
        {"zscore_anomaly": False, "zscore_value": 0.4},
        {"zscore_anomaly": False, "zscore_value": 1.1},
        {"zscore_anomaly": True, "zscore_value": 4.2},
    ]
    mock_iforest = lambda evs: [
        {"isolation_forest_anomaly": False, "isolation_forest_score": 0.12},
        {"isolation_forest_anomaly": False, "isolation_forest_score": 0.05},
        {"isolation_forest_anomaly": True, "isolation_forest_score": -0.38},
    ]

    pipeline = HybridSecOpsPipeline(
        db_path=str(db_file),
        zscore_runner=mock_zscore,
        iforest_runner=mock_iforest,
    )

    results = pipeline.run_from_jsonl(str(jsonl_file), persist=True)

    assert len(results) == 3
    assert results[0].is_anomaly is False
    assert results[0].severity == Severity.LOW

    assert results[1].is_anomaly is True
    assert results[1].severity == Severity.CRITICAL
    assert "CLOUDTRAIL_RULES" in results[1].triggered_detectors
    assert len(results[1].rule_violations) == 2

    assert results[2].is_anomaly is True
    assert results[2].severity == Severity.HIGH
    assert results[2].triggered_detectors == ["Z_SCORE", "ISOLATION_FOREST"]

    persisted_alerts = pipeline.repository.query_alerts()
    assert len(persisted_alerts) >= 2