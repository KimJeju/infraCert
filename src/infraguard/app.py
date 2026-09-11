"""PySide6 진입점.

- 고DPI 스케일링 (고객사 PC 해상도 제각각)
- workspace 생성, 저장소·크리덴셜 세션 초기화
- 온라인 동작 없음(폐쇄망)
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    from PySide6.QtWidgets import QApplication

    from infraguard import config
    from infraguard.credentials.session import CredentialSession
    from infraguard.orchestrator.results_store import ResultsStore
    from infraguard.ui.main_window import AppContext, MainWindow
    from infraguard.ui.theme import DARK_QSS
    from infraguard.workspace.manager import Workspace

    cfg = config.load()

    ws = Workspace()
    layout = ws.create()

    # 처리되지 않은 예외 → workspace/logs/crash.log (마스킹). --noconsole 빌드의 유일한 단서.
    from infraguard import crashlog

    def _notify(path: str) -> None:
        from PySide6.QtWidgets import QApplication, QMessageBox
        if QApplication.instance() is not None:
            QMessageBox.critical(None, "InfraGuard 오류",
                                 f"예기치 않은 오류가 발생했습니다.\n기록: {path}\n(크리덴셜은 마스킹됩니다)")

    crashlog.install(layout.logs / "crash.log", notify=_notify)

    from infraguard.assets.store import AssetStore
    assets = AssetStore(layout.assets_db)
    results = ResultsStore(layout.results_db)
    ws.register_closable(assets)
    ws.register_closable(results)

    creds = CredentialSession(idle_seconds=int(cfg.get("idle_lock_minutes", 15)) * 60)

    app = QApplication(sys.argv)
    app.setApplicationName("InfraGuard")
    app.setStyleSheet(DARK_QSS)

    # 단일 인스턴스: 같은 workspace 를 두 창이 열면 종료 시 완전삭제가 상대 창의 DB 핸들에 막힌다(09-11 실측).
    from PySide6.QtCore import QLockFile
    from PySide6.QtWidgets import QMessageBox

    from infraguard.workspace.layout import app_root
    lock = QLockFile(str(app_root() / ".infraguard.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        QMessageBox.warning(None, "InfraGuard", "이미 실행 중입니다. 열려 있는 창을 사용하세요.")
        return 2
    app._ig_lock = lock  # noqa: SLF001 - 프로세스 수명 동안 잡아 둔다

    ctx = AppContext(workspace=ws, assets=assets, results=results, creds=creds, config=cfg)
    win = MainWindow(ctx)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
