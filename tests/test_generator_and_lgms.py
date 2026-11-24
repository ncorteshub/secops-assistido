"""Testes da camada Origem / LGMS: geração de logs JSONL e normalização canônica."""

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest
from pydantic import ValidationError

from secops_core.generator import (
    ANOMALOUS_IPS,
    NORMAL_EVENTS,
    NORMAL_IPS,
    generate_base_event,
    generate_logs,
)
from secops_core.lgms import CanonicalLog, LGMSProcessor


def _valid_raw_event(**overrides) -> dict:
    """Constrói um evento bruto válido no formato esperado pelo schema LGMS."""
    payload = {
        "timestamp": "2026-11-24T12:00:00Z",
        "event_id": "evt-lgms-001",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "user_identity": {"arn": "arn:aws:iam::123456789012:user/alice"},
        "source_ip": "10.0.0.15",
        "aws_region": "us-east-1",
        "status": "Success",
        "error_code": None,
        "request_count": 3,
        "bytes_transferred": 1024,
    }
    payload.update(overrides)
    return payload


class TestLogGenerator:
    """Valida a geração controlada de logs simulados em JSONL isolado."""

    def test_generate_base_event_normal_and_anomalous_ips(self):
        ts = datetime(2026, 11, 24, 10, 30, 0)
        normal_ev = generate_base_event(ts, is_anomaly=False)
        anomalous_ev = generate_base_event(ts, is_anomaly=True)

        assert normal_ev["source_ip"] in NORMAL_IPS
        assert anomalous_ev["source_ip"] in ANOMALOUS_IPS
        assert (normal_ev["event_source"], normal_ev["event_name"]) in NORMAL_EVENTS
        assert normal_ev["timestamp"] == "2026-11-24T10:30:00Z"

    def test_generate_logs_writes_exact_count_and_chronological_jsonl(self, test_logs_path: Path):
        generate_logs(
            num_records=50,
            seed=42,
            anomaly_rate=0.2,
            output_file=str(test_logs_path),
        )

        assert test_logs_path.exists()
        lines = test_logs_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 50

        records = [json.loads(line) for line in lines]
        timestamps = [rec["timestamp"] for rec in records]
        assert timestamps == sorted(timestamps)

        for rec in records:
            validated = CanonicalLog(**rec)
            assert validated.request_count >= 1
            assert validated.bytes_transferred >= 100

    def test_generate_logs_zero_vs_high_anomaly_rate(self, tmp_path: Path):
        normal_file = tmp_path / "normal_only.jsonl"
        anomalous_file = tmp_path / "anomalous_heavy.jsonl"

        generate_logs(num_records=30, seed=10, anomaly_rate=0.0, output_file=str(normal_file))
        generate_logs(num_records=40, seed=10, anomaly_rate=1.0, output_file=str(anomalous_file))

        normal_records = [json.loads(line) for line in normal_file.read_text(encoding="utf-8").splitlines()]
        assert all(rec["source_ip"] in NORMAL_IPS for rec in normal_records)
        assert all((rec["event_source"], rec["event_name"]) in NORMAL_EVENTS for rec in normal_records)

        anomalous_records = [json.loads(line) for line in anomalous_file.read_text(encoding="utf-8").splitlines()]
        suspicious_indicators = [
            rec
            for rec in anomalous_records
            if rec["source_ip"] in ANOMALOUS_IPS
            or rec["event_name"] in {"PutUserPolicy", "DeleteTrail"}
            or rec["bytes_transferred"] >= 500_000
            or datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00")).hour in {2, 3, 4}
        ]
        assert len(suspicious_indicators) > 0


class TestLGMSNormalization:
    """Valida o parsing, tipagem e resiliência a registros malformados no schema LGMS."""

    def test_canonical_log_validates_required_fields_and_types(self):
        raw = _valid_raw_event(request_count="7", bytes_transferred="2048", error_code="AccessDenied")
        model = CanonicalLog(**raw)

        assert isinstance(model.timestamp, datetime)
        assert model.request_count == 7
        assert model.bytes_transferred == 2048
        assert model.user_identity.arn == "arn:aws:iam::123456789012:user/alice"
        assert model.error_code == "AccessDenied"

    @pytest.mark.parametrize(
        "invalid_patch",
        [
            {"event_id": None},
            {"timestamp": "not-a-timestamp"},
            {"user_identity": "invalid-string-instead-of-dict"},
            {"request_count": "not-an-int"},
            {"bytes_transferred": "invalid-bytes"},
        ],
    )
    def test_canonical_log_rejects_invalid_schema_or_types(self, invalid_patch: dict):
        bad_payload = _valid_raw_event(**invalid_patch)
        with pytest.raises(ValidationError):
            CanonicalLog(**bad_payload)

    def test_canonical_log_rejects_missing_required_field(self):
        incomplete = _valid_raw_event()
        del incomplete["event_name"]
        with pytest.raises(ValidationError):
            CanonicalLog(**incomplete)

    def test_lgms_processor_skips_malformed_json_and_invalid_records(
        self, test_logs_path: Path, caplog: pytest.LogCaptureFixture
    ):
        valid_1 = _valid_raw_event(event_id="evt-ok-1", source_ip="10.0.0.1", status="Success")
        valid_2 = _valid_raw_event(
            event_id="evt-ok-2",
            source_ip="10.0.0.1",
            status="Failure",
            error_code="AccessDenied",
            timestamp="2026-11-24T15:30:00Z",
        )
        missing_field_record = _valid_raw_event(event_id="evt-bad-schema")
        del missing_field_record["aws_region"]

        bad_type_record = _valid_raw_event(event_id="evt-bad-type", request_count="abc")

        lines = [
            "",
            json.dumps(valid_1),
            "{broken-json-line",
            json.dumps(missing_field_record),
            "   ",
            json.dumps(bad_type_record),
            json.dumps(valid_2),
        ]
        test_logs_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        processor = LGMSProcessor(filepath=str(test_logs_path))
        with caplog.at_level("WARNING"):
            processor.parse_file()

        assert len(processor.parsed_logs) == 2
        assert [log.event_id for log in processor.parsed_logs] == ["evt-ok-1", "evt-ok-2"]
        assert "JSON Invalido" in caplog.text
        assert "Fora do Schema" in caplog.text

    def test_lgms_feature_matrix_engineering_and_empty_state(self, test_logs_path: Path):
        test_logs_path.write_text("", encoding="utf-8")
        empty_processor = LGMSProcessor(filepath=str(test_logs_path))
        empty_processor.parse_file()
        assert empty_processor.get_feature_matrix().empty

        generate_logs(num_records=25, seed=99, anomaly_rate=0.2, output_file=str(test_logs_path))
        processor = LGMSProcessor(filepath=str(test_logs_path))
        processor.parse_file()
        assert len(processor.parsed_logs) == 25

        df = processor.get_feature_matrix()
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 25
        assert "user_identity" not in df.columns
        for col in [
            "user_arn",
            "hour_of_day",
            "day_of_week",
            "is_error",
            "ip_freq_count",
            "user_freq_count",
        ]:
            assert col in df.columns
        assert set(df["is_error"].unique()).issubset({0, 1})
