"""자산 저장소 — workspace/assets.db (SQLite).

호스트 1건 = 1행(JSON). 비밀정보는 저장하지 않는다(모델이 애초에 보유하지 않음).
workspace 안에만 쓰므로 완전삭제 대상에 자동 포함된다.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from infraguard.assets.models import Host


class AssetStore:
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS hosts (host_id TEXT PRIMARY KEY, data TEXT NOT NULL)"
        )
        self._conn.commit()

    def upsert(self, host: Host) -> None:
        self._conn.execute(
            "INSERT INTO hosts(host_id, data) VALUES(?, ?) "
            "ON CONFLICT(host_id) DO UPDATE SET data=excluded.data",
            (host.host_id, host.model_dump_json()),
        )
        self._conn.commit()

    def delete(self, host_id: str) -> None:
        self._conn.execute("DELETE FROM hosts WHERE host_id=?", (host_id,))
        self._conn.commit()

    def get(self, host_id: str) -> Host | None:
        row = self._conn.execute(
            "SELECT data FROM hosts WHERE host_id=?", (host_id,)
        ).fetchone()
        return Host.model_validate_json(row[0]) if row else None

    def all(self) -> list[Host]:
        rows = self._conn.execute("SELECT data FROM hosts").fetchall()
        return [Host.model_validate_json(r[0]) for r in rows]

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
