"""작업공간 배치 — 단일 정의.

고객사 PC 반입형이므로 %APPDATA%·레지스트리·사용자 프로필을 사용하지 않는다.
실행 파일 위치 기준 workspace/ 하나에만 쓴다. 여기만 지우면 잔류물이 사라진다.

다른 모듈이 임의 경로에 파일을 쓰는 것을 금지한다.
(tests/failure/test_no_stray_writes.py 에서 검증)
"""

from __future__ import annotations

import sys
from pathlib import Path

WORKSPACE_DIRNAME = "workspace"


def app_root() -> Path:
    """실행 파일(또는 소스 트리)이 있는 폴더."""
    if getattr(sys, "frozen", False):          # PyInstaller onedir
        return Path(sys.executable).resolve().parent
    # 소스 실행: src/infraguard/workspace/layout.py -> 프로젝트 루트
    return Path(__file__).resolve().parents[3]


class Layout:
    """workspace 하위 경로를 계산한다. 경로 생성은 Manager 가 한다."""

    def __init__(self, root: Path | None = None) -> None:
        self.root: Path = (root or (app_root() / WORKSPACE_DIRNAME)).resolve()

    # --- 파일 ---
    @property
    def assets_db(self) -> Path:
        return self.root / "assets.db"

    @property
    def results_db(self) -> Path:
        return self.root / "results.db"

    # --- 디렉터리 ---
    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def exports(self) -> Path:
        return self.root / "exports"

    def scan_dir(self, scan_id: str) -> Path:
        return self.artifacts / _safe(scan_id)

    def host_dir(self, scan_id: str, host_id: str) -> Path:
        return self.scan_dir(scan_id) / _safe(host_id)

    def all_dirs(self) -> list[Path]:
        return [self.artifacts, self.logs, self.tmp, self.exports]

    def contains(self, p: Path) -> bool:
        """p 가 workspace 안인가. 외부 쓰기 차단 검사용."""
        try:
            p.resolve().relative_to(self.root)
        except ValueError:
            return False
        return True


_UNSAFE = set('<>:"/\\|?*')


def _safe(name: str) -> str:
    """경로 조각으로 안전한 이름. path traversal·드라이브 문자 차단."""
    cleaned = "".join("_" if c in _UNSAFE or ord(c) < 32 else c for c in name).strip(" .")
    return cleaned or "_"
