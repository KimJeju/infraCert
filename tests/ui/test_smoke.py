"""UI 스모크 — 오프스크린에서 MainWindow 가 뜨고 자산 CRUD 가 트리에 반영되는지.

PySide6 가 없거나 오프스크린 플랫폼 초기화가 불가하면 건너뛴다.
"""
import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from infraguard.assets.models import Host  # noqa: E402
from infraguard.assets.store import AssetStore  # noqa: E402
from infraguard.core.ids import new_host_id  # noqa: E402
from infraguard.credentials.session import CredentialSession  # noqa: E402
from infraguard.orchestrator.results_store import ResultsStore  # noqa: E402
from infraguard.ui.main_window import AppContext, MainWindow  # noqa: E402
from infraguard.workspace.manager import Workspace  # noqa: E402


@pytest.fixture
def ctx(tmp_path):
    ws = Workspace(tmp_path / "workspace")
    layout = ws.create()
    assets = AssetStore(layout.assets_db)
    results = ResultsStore(layout.results_db)
    # app.py 와 동일하게 등록 — 종료 시 sanitize 가 DB 를 닫고 삭제할 수 있어야 한다
    ws.register_closable(assets)
    ws.register_closable(results)
    return AppContext(workspace=ws, assets=assets, results=results,
                      creds=CredentialSession(), config={})


def test_mainwindow_builds_and_shows_tabs(qtbot, ctx):
    win = MainWindow(ctx)
    qtbot.addWidget(win)
    # 고정 탭 6 (대시보드/진단/결과/수동확인/룰팩/설정). 터미널·파일은 호스트별 동적 탭.
    titles = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    for key in ("대시보드", "진단", "결과", "수동확인", "룰팩", "설정"):
        assert any(key in t for t in titles), key
    assert win.tabs.count() == win.FIXED_TABS == 6
    assert win.pack is not None and win.pack.runnable, win.pack and win.pack.problems


def test_asset_crud_reflects_in_tree(qtbot, ctx):
    win = MainWindow(ctx)
    qtbot.addWidget(win)
    h = Host(host_id=new_host_id(), name="web01", address="10.0.0.9",
             project="고객사A", group="WEB")
    ctx.assets.upsert(h)
    win._refresh_assets()
    assert win.model.find_host_item(h.host_id) is not None
    ctx.assets.delete(h.host_id)
    win._refresh_assets()
    assert win.model.find_host_item(h.host_id) is None
