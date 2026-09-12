"""결과 체크포인트 — workspace/results.db (SQLite).

호스트 하나가 끝날 때마다 즉시 기록한다. 앱이 죽어도 완료분은 남는다(§3.1 체크포인트).
수동확인 판정(analyst) 도 여기에 되쓴다. 스크립트 판정과 출처(verdict_source)로 구분된다.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from infraguard.core.models import HostResult, ScanResult
from infraguard.core.status import Status


class ResultsStore:
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, meta TEXT)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS host_results ("
            "scan_id TEXT, host_id TEXT, data TEXT, "
            "PRIMARY KEY(scan_id, host_id))"
        )
        self._conn.commit()

    # --- 쓰기 ---
    def start_scan(self, scan: ScanResult) -> None:
        meta = {
            "engine_version": scan.engine_version,
            "rule_pack_version": scan.rule_pack_version,
            "rule_pack_sha256": scan.rule_pack_sha256,
            "profile": scan.profile,
            "started_at": scan.started_at.isoformat(),
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        }
        self._conn.execute(
            "INSERT INTO scans(scan_id, meta) VALUES(?, ?) "
            "ON CONFLICT(scan_id) DO UPDATE SET meta=excluded.meta",
            (scan.scan_id, json.dumps(meta, ensure_ascii=False)),
        )
        self._conn.commit()

    def save_host(self, scan_id: str, host: HostResult) -> None:
        """체크포인트. host_finished 시 즉시 호출."""
        self._conn.execute(
            "INSERT INTO host_results(scan_id, host_id, data) VALUES(?, ?, ?) "
            "ON CONFLICT(scan_id, host_id) DO UPDATE SET data=excluded.data",
            (scan_id, host.host_id, host.model_dump_json()),
        )
        self._conn.commit()

    def finish_scan(self, scan_id: str, finished_at: datetime) -> None:
        row = self._conn.execute("SELECT meta FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        meta = json.loads(row[0]) if row else {}
        meta["finished_at"] = finished_at.isoformat()
        self._conn.execute("UPDATE scans SET meta=? WHERE scan_id=?",
                           (json.dumps(meta, ensure_ascii=False), scan_id))
        self._conn.commit()

    def set_verdict(self, scan_id: str, host_id: str, rule_id: str,
                    status: str, note: str) -> None:
        """수동확인 판정 되쓰기. verdict_source=analyst 로 표시한다."""
        host = self.get_host(scan_id, host_id)
        if host is None:
            return
        for r in host.results:
            if r.rule_id == rule_id:
                r.status = Status(status)
                r.reason = note or "분석자 판정"
                r.verdict_source = "analyst"
                r.analyst_note = note
                break
        self.save_host(scan_id, host)

    # --- 읽기 ---
    def get_host(self, scan_id: str, host_id: str) -> HostResult | None:
        row = self._conn.execute(
            "SELECT data FROM host_results WHERE scan_id=? AND host_id=?",
            (scan_id, host_id),
        ).fetchone()
        return HostResult.model_validate_json(row[0]) if row else None

    def load_scan(self, scan_id: str) -> ScanResult | None:
        row = self._conn.execute("SELECT meta FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if not row:
            return None
        meta = json.loads(row[0])
        hosts = [
            HostResult.model_validate_json(r[0])
            for r in self._conn.execute(
                "SELECT data FROM host_results WHERE scan_id=? ORDER BY host_id", (scan_id,)
            ).fetchall()
        ]
        return ScanResult(
            scan_id=scan_id,
            engine_version=meta.get("engine_version", ""),
            rule_pack_version=meta.get("rule_pack_version"),
            rule_pack_sha256=meta.get("rule_pack_sha256"),
            profile=meta.get("profile"),
            started_at=datetime.fromisoformat(meta["started_at"]),
            finished_at=datetime.fromisoformat(meta["finished_at"]) if meta.get("finished_at") else None,
            hosts=hosts,
        )

    def list_scans(self) -> list[tuple[str, dict]]:
        rows = self._conn.execute("SELECT scan_id, meta FROM scans").fetchall()
        out = [(sid, json.loads(meta)) for sid, meta in rows]
        out.sort(key=lambda x: x[1].get("started_at", ""), reverse=True)
        return out

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
