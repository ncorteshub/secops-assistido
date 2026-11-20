import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

DEFAULT_DB_PATH = Path("secops.db")


class SecOpsRepository:
    """Camada de persistência SQLite otimizada para logs normalizados, scores e alertas."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            # Otimizações de alta performance para escrita em lote
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = OFF;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute("PRAGMA cache_size = -64000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Cria a tabela principal e os índices caso ainda não existam."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS security_alerts (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            user_identity TEXT,
            event_name TEXT,
            event_source TEXT,
            aws_region TEXT,
            raw_normalized_json TEXT NOT NULL,
            zscore_value REAL DEFAULT 0.0,
            is_zscore_anomaly INTEGER DEFAULT 0,
            iforest_score REAL DEFAULT 0.0,
            is_iforest_anomaly INTEGER DEFAULT 0,
            cloudtrail_rules_triggered TEXT DEFAULT '[]',
            final_severity TEXT NOT NULL DEFAULT 'LOW',
            is_anomaly INTEGER NOT NULL DEFAULT 0,
            ai_explanation TEXT,
            processed_at TEXT NOT NULL
        );
        """

        create_indexes_sql = [
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_is_anomaly ON security_alerts(is_anomaly);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(final_severity);",
        ]

        with self._get_connection() as conn:
            conn.execute(create_table_sql)
            for index_sql in create_indexes_sql:
                conn.execute(index_sql)

    def bulk_insert(self, records: List[Dict[str, Any]]) -> int:
        """
        Insere múltiplos eventos processados em uma única transação em < 100ms.
        Usa INSERT OR IGNORE no event_id (PRIMARY KEY) para garantir idempotência.
        """
        if not records:
            return 0

        now_iso = datetime.now(timezone.utc).isoformat()
        dumps = json.dumps

        insert_sql = """
        INSERT OR IGNORE INTO security_alerts (
            event_id,
            timestamp,
            source_ip,
            user_identity,
            event_name,
            event_source,
            aws_region,
            raw_normalized_json,
            zscore_value,
            is_zscore_anomaly,
            iforest_score,
            is_iforest_anomaly,
            cloudtrail_rules_triggered,
            final_severity,
            is_anomaly,
            ai_explanation,
            processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        rows_to_insert = [
            (
                rec["event_id"],
                rec["timestamp"] if isinstance(rec["timestamp"], str) else str(rec["timestamp"]),
                rec.get("source_ip"),
                rec.get("user_identity"),
                rec.get("event_name"),
                rec.get("event_source"),
                rec.get("aws_region"),
                (
                    rec["raw_normalized_json"]
                    if isinstance(rec.get("raw_normalized_json"), str)
                    else dumps(rec.get("raw_normalized_json") or rec, default=str)
                ),
                float(rec.get("zscore_value", 0.0)),
                1 if rec.get("is_zscore_anomaly") else 0,
                float(rec.get("iforest_score", 0.0)),
                1 if rec.get("is_iforest_anomaly") else 0,
                (
                    "[]"
                    if not rec.get("cloudtrail_rules_triggered")
                    else (
                        rec["cloudtrail_rules_triggered"]
                        if isinstance(rec["cloudtrail_rules_triggered"], str)
                        else dumps(rec["cloudtrail_rules_triggered"])
                    )
                ),
                rec.get("final_severity", "LOW"),
                1 if rec.get("is_anomaly") else 0,
                rec.get("ai_explanation"),
                rec.get("processed_at", now_iso),
            )
            for rec in records
        ]

        with self._get_connection() as conn:
            cursor = conn.executemany(insert_sql, rows_to_insert)
            return cursor.rowcount

    def update_ai_explanation(self, event_id: str, explanation: str) -> bool:
        """Atualiza a explicação gerada pela IA para um alerta específico."""
        update_sql = """
        UPDATE security_alerts
        SET ai_explanation = ?
        WHERE event_id = ?;
        """
        with self._get_connection() as conn:
            cursor = conn.execute(update_sql, (explanation, event_id))
            return cursor.rowcount > 0

    def query_alerts(
        self,
        only_anomalies: bool = False,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Consulta logs/alertas com filtros opcionais e deserialização automática."""
        conditions: List[str] = []
        params: List[Any] = []

        if only_anomalies:
            conditions.append("is_anomaly = 1")

        if severity:
            conditions.append("final_severity = ?")
            params.append(severity.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query_sql = f"""
        SELECT *
        FROM security_alerts
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?;
        """
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query_sql, params).fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["is_zscore_anomaly"] = bool(item["is_zscore_anomaly"])
            item["is_iforest_anomaly"] = bool(item["is_iforest_anomaly"])
            item["is_anomaly"] = bool(item["is_anomaly"])
            item["cloudtrail_rules_triggered"] = json.loads(
                item["cloudtrail_rules_triggered"] or "[]"
            )
            results.append(item)

        return results