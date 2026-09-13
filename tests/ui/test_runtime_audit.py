"""런타임 전수 감사 — 모든 모듈 import, 모든 페이지·다이얼로그 생성, 최소 높이가 노트북 창을 넘으면 스크롤 영역이 있어야 한다."""

from __future__ import annotations

import importlib
import os
import pkgutil
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import infraguard  # noqa: E402
from PySide6.QtWidgets import QScrollArea  # noqa: E402

from infraguard import config  # noqa: E402
from infraguard.assets.models import Host  # noqa: E402
from infraguard.rulepack import loader  # noqa: E402
from infraguard.workspace.layout import Layout  # noqa: E402

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"
CONTENT_H = 560      # 1366x768 노트북에서 타이틀바·메뉴·탭을 빼고 콘텐츠에 남는 대략의 높이


def test_every_module_imports() -> None:
    failed = []
    for m in pkgutil.walk_packages(infraguard.__path__, "infraguard."):
        try:
            importlib.import_module(m.name)
        except Exception as e:  # noqa: BLE001
            failed.append(f"{m.name}: {type(e).__name__}: {e}")
    assert not failed, failed


def _builders():
    pack = loader.load(PACK)
    from infraguard.ui.dialogs import AssetEditDialog, CredPromptDialog, ExceptionDialog, HostKeyDialog
    from infraguard.ui.pages.assets import AssetsPage
    from infraguard.ui.pages.dashboard import DashboardPage
    from infraguard.ui.pages.reports import ReportsPage
    from infraguard.ui.pages.manual import ManualBenchPage
    from infraguard.ui.pages.result import ResultPage
    from infraguard.ui.pages.rulepack import RulePackPage
    from infraguard.ui.pages.scan import ScanPage
    from infraguard.ui.pages.settings import SettingsPage
    hosts = [Host(host_id=f"h{i}", name=f"host{i}", address=f"10.0.0.{i}") for i in range(12)]

    def scan():
        p = ScanPage()
        p.set_profiles([(k, v.name, v.description) for k, v in pack.profiles.items()])
        p.set_targets(hosts)
        p.begin(hosts)
        return p

    def rulepack():
        p = RulePackPage()
        p.load(pack)
        p.tester.set_spec(pack.specs["U-16"])
        return p

    return {
        "dashboard": DashboardPage, "assets": AssetsPage, "reports": ReportsPage, "scan": scan, "result": ResultPage, "manual": ManualBenchPage,
        "rulepack": rulepack, "settings": lambda: SettingsPage(config.load(), Layout(), "0.1", "kisa-2026"),
        "dlg.asset": lambda: AssetEditDialog(Host(host_id="h", name="n", address="a")),
        "dlg.cred": lambda: CredPromptDialog("root@x:22", "root"),
        "dlg.exception": lambda: ExceptionDialog("h", "U-01", "x"),
        "dlg.hostkey": lambda: HostKeyDialog("h", "ssh-ed25519", "SHA256:abc"),
    }


@pytest.mark.parametrize("name", list(_builders()))
def test_widget_fits_or_scrolls(qtbot, name: str) -> None:  # noqa: ANN001
    w = _builders()[name]()
    qtbot.addWidget(w)
    w.resize(1100, CONTENT_H)
    w.show()
    mh = w.minimumSizeHint().height()
    scrolls = w.findChildren(QScrollArea)
    assert mh <= CONTENT_H or scrolls, f"{name}: 최소 높이 {mh} > {CONTENT_H} 인데 스크롤 영역 없음"
