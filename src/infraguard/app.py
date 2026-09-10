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

    ctx = AppContext(workspace=ws, assets=assets, results=results, creds=creds, config=cfg)
    win = MainWindow(ctx)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
