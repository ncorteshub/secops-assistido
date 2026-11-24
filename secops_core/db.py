import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

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

            # Garante migração de schema caso a coluna ai_explanation não exista
            cursor = conn.execute("PRAGMA table_info(security_alerts);")
            columns = [row["name"] for row in cursor.fetchall()]
            if "ai_explanation" not in columns:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN ai_explanation TEXT;")

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
                (
                    dumps(rec["user_identity"], default=str)
                    if isinstance(rec.get("user_identity"), dict)
                    else rec.get("user_identity")
                ),
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

    def get_alert_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Busca um alerta específico pelo event_id com deserialização automática."""
        query_sql = "SELECT * FROM security_alerts WHERE event_id = ? LIMIT 1;"
        with self._get_connection() as conn:
            row = conn.execute(query_sql, (event_id,)).fetchone()
            if row is None:
                return None
            item = dict(row)
            item["is_zscore_anomaly"] = bool(item["is_zscore_anomaly"])
            item["is_iforest_anomaly"] = bool(item["is_iforest_anomaly"])
            item["is_anomaly"] = bool(item["is_anomaly"])
            try:
                item["cloudtrail_rules_triggered"] = json.loads(
                    item["cloudtrail_rules_triggered"] or "[]"
                )
            except Exception:
                item["cloudtrail_rules_triggered"] = []

            try:
                item["user_identity"] = json.loads(item["user_identity"])
            except Exception:
                pass

            try:
                item["raw_normalized_json"] = json.loads(item["raw_normalized_json"])
            except Exception:
                pass

            return item

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

    def get_logs_paginated(
        self,
        is_anomaly: Optional[bool] = None,
        severity: Optional[str] = None,
        event_name: Optional[str] = None,
        user: Optional[str] = None,
        source_ip: Optional[str] = None,
        detector_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Consulta logs com filtros combináveis e paginação segura via parâmetros vinculados."""
        conditions: List[str] = []
        params: List[Any] = []

        if is_anomaly is not None:
            conditions.append("is_anomaly = ?")
            params.append(1 if is_anomaly else 0)

        if severity is not None:
            conditions.append("final_severity = ?")
            params.append(severity.upper())

        if event_name is not None:
            conditions.append("event_name = ?")
            params.append(event_name)

        if source_ip is not None:
            conditions.append("source_ip = ?")
            params.append(source_ip)

        if user is not None:
            conditions.append("user_identity LIKE ?")
            params.append(f"%{user}%")

        if detector_type is not None:
            dt = detector_type.lower()
            if dt in ("statistical", "zscore"):
                conditions.append("is_zscore_anomaly = 1")
            elif dt in ("ml", "iforest"):
                conditions.append("is_iforest_anomaly = 1")
            elif dt in ("rule", "cloudtrail_rules", "rules"):
                conditions.append("(cloudtrail_rules_triggered != '[]' AND cloudtrail_rules_triggered IS NOT NULL)")
            elif dt == "hybrid":
                conditions.append(
                    "((is_zscore_anomaly = 1) + (is_iforest_anomaly = 1) + "
                    "(CASE WHEN cloudtrail_rules_triggered != '[]' AND cloudtrail_rules_triggered IS NOT NULL THEN 1 ELSE 0 END)) > 1"
                )

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_sql = f"SELECT COUNT(*) AS total FROM security_alerts {where_clause};"
        query_sql = f"""
        SELECT *
        FROM security_alerts
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?;
        """

        with self._get_connection() as conn:
            total = conn.execute(count_sql, params).fetchone()["total"]
            query_params = list(params) + [limit, offset]
            rows = conn.execute(query_sql, query_params).fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["is_zscore_anomaly"] = bool(item["is_zscore_anomaly"])
            item["is_iforest_anomaly"] = bool(item["is_iforest_anomaly"])
            item["is_anomaly"] = bool(item["is_anomaly"])
            try:
                item["cloudtrail_rules_triggered"] = json.loads(
                    item["cloudtrail_rules_triggered"] or "[]"
                )
            except Exception:
                item["cloudtrail_rules_triggered"] = []

            try:
                item["user_identity"] = json.loads(item["user_identity"])
            except Exception:
                pass

            try:
                item["raw_normalized_json"] = json.loads(item["raw_normalized_json"])
            except Exception:
                pass

            results.append(item)

        return total, results

    def get_stats(self) -> Dict[str, Any]:
        """Gera resumo executivo consolidado a partir do SQLite."""
        with self._get_connection() as conn:
            # 1. Totais gerais
            tot_row = conn.execute("""
                SELECT
                    COUNT(*) AS total_logs,
                    COALESCE(SUM(is_anomaly), 0) AS total_anomalies
                FROM security_alerts;
            """).fetchone()

            total_logs = tot_row["total_logs"] if tot_row else 0
            total_anomalies = tot_row["total_anomalies"] if tot_row else 0
            anomaly_rate = round(total_anomalies / total_logs, 4) if total_logs > 0 else 0.0

            # 2. Agrupamento por severidade
            sev_rows = conn.execute("""
                SELECT final_severity, COUNT(*) AS count
                FROM security_alerts
                GROUP BY final_severity;
            """).fetchall()
            by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for r in sev_rows:
                by_severity[r["final_severity"]] = r["count"]

            # 3. Agrupamento por detector
            det_row = conn.execute("""
                SELECT
                    COALESCE(SUM(CASE WHEN is_zscore_anomaly = 1 THEN 1 ELSE 0 END), 0) AS zscore_cnt,
                    COALESCE(SUM(CASE WHEN is_iforest_anomaly = 1 THEN 1 ELSE 0 END), 0) AS iforest_cnt,
                    COALESCE(SUM(CASE WHEN cloudtrail_rules_triggered != '[]' AND cloudtrail_rules_triggered IS NOT NULL THEN 1 ELSE 0 END), 0) AS rules_cnt,
                    COALESCE(SUM(CASE WHEN (
                        (is_zscore_anomaly = 1) +
                        (is_iforest_anomaly = 1) +
                        (CASE WHEN cloudtrail_rules_triggered != '[]' AND cloudtrail_rules_triggered IS NOT NULL THEN 1 ELSE 0 END)
                    ) > 1 THEN 1 ELSE 0 END), 0) AS hybrid_cnt
                FROM security_alerts;
            """).fetchone()

            z_cnt = det_row["zscore_cnt"] if det_row else 0
            if_cnt = det_row["iforest_cnt"] if det_row else 0
            r_cnt = det_row["rules_cnt"] if det_row else 0
            hyb_cnt = det_row["hybrid_cnt"] if det_row else 0

            by_detector = {
                "statistical": z_cnt,
                "zscore": z_cnt,
                "ml": if_cnt,
                "iforest": if_cnt,
                "rule": r_cnt,
                "cloudtrail_rules": r_cnt,
                "hybrid": hyb_cnt,
            }

            # 4. Top eventos
            top_ev_rows = conn.execute("""
                SELECT event_name, COUNT(*) AS count
                FROM security_alerts
                WHERE event_name IS NOT NULL AND event_name != ''
                GROUP BY event_name
                ORDER BY count DESC
                LIMIT 10;
            """).fetchall()
            top_events = [{"event_name": r["event_name"], "count": r["count"]} for r in top_ev_rows]

            # 5. Top source IPs
            top_ip_rows = conn.execute("""
                SELECT source_ip, COUNT(*) AS count
                FROM security_alerts
                WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10;
            """).fetchall()
            top_source_ips = [{"source_ip": r["source_ip"], "count": r["count"]} for r in top_ip_rows]

            return {
                "total_logs": total_logs,
                "total_anomalies": total_anomalies,
                "anomaly_rate": anomaly_rate,
                "by_severity": by_severity,
                "by_detector": by_detector,
                "top_events": top_events,
                "top_source_ips": top_source_ips,
            }