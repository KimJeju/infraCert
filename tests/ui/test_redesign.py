"""UI 재설계 셸 — Nav/스택, 명령 팔레트, 세션 종료 다이얼로그, 결과 3-pane 링크, 세션 탭."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QWidget  # noqa: E402

from infraguard.core.status import Status  # noqa: E402
from infraguard.ui.exit_dialog import SessionEndDialog  # noqa: E402
from infraguard.ui.nav import NavRail  # noqa: E402
from infraguard.ui.pages.sessions import SessionTabs  # noqa: E402
from infraguard.ui.palette import Command, CommandPalette  # noqa: E402
from infraguard.ui.theme import status_label  # noqa: E402


def test_nav_groups_badges_and_selection(qtbot) -> None:  # noqa: ANN001
    nav = NavRail()
    qtbot.addWidget(nav)
    got: list[str] = []
    nav.selected.connect(got.append)
    assert nav.keys()[:5] == ["overview", "assets", "scan", "findings", "reports"] and nav.keys()[-1] == "settings"
    nav._btns["scan"].click()
    assert got == ["scan"] and nav._btns["scan"].isChecked() and not nav._btns["overview"].isChecked()
    nav.set_badge("terminal", "(2)")
    assert "(2)" in nav._btns["terminal"].text()
    nav.set_badge("terminal", "")
    assert "(" not in nav._btns["terminal"].text()


def test_palette_filters_and_runs(qtbot) -> None:  # noqa: ANN001
    ran: list[str] = []
    cmds = [Command("이동", "결과", lambda: ran.append("findings"), "findings"),
            Command("진단", "모든 자산 진단", lambda: ran.append("scan-all"), "scan all")]
    provider = lambda q: [Command("자산", f"WEB-01 ({q})", lambda: ran.append("host"))] if "web" in q.lower() else []  # noqa: E731
    parent = QWidget()
    qtbot.addWidget(parent)
    pal = CommandPalette(cmds, providers=[provider], parent=parent)
    pal.refresh("")
    assert pal.list.count() == 2
    pal.refresh("진단")
    assert pal.list.count() == 1 and "모든 자산" in pal.list.item(0).text()
    pal.refresh("web")
    assert pal.list.count() == 1 and "WEB-01" in pal.list.item(0).text()
    pal.list.setCurrentRow(0)
    pal._run_current()
    assert ran == ["host"]


def test_session_end_dialog_choices(qtbot) -> None:  # noqa: ANN001
    d = SessionEndDialog(unexported=True, default_wipe=True)
    qtbot.addWidget(d)
    assert d.wipe_workspace and d.wipe_cred.isChecked() and not d.wipe_cred.isEnabled()
    assert "삭제" in d.ok.text()
    d.wipe_ws.setChecked(False)
    assert not d.wipe_workspace and d.ok.text() == "종료"
    d2 = SessionEndDialog(unexported=False, default_wipe=False)
    qtbot.addWidget(d2)
    assert not d2.wipe_workspace and d2.ok.text() == "종료"


def test_session_tabs_add_remove_state(qtbot) -> None:  # noqa: ANN001
    st = SessionTabs("terminal", "없음")
    qtbot.addWidget(st)
    counts: list[int] = []
    st.count_changed.connect(counts.append)
    p = QWidget()
    st.add(p, "● web01")
    assert st.pages() == [p] and counts[-1] == 1 and st.tabs.count() == 1
    st.set_state(p, "connected", "web01")
    assert "web01" in st.tabs.tabText(0)
    st.set_multi_count(2)
    assert "2" in st.multi_n.text()
    st.remove(p)
    assert st.pages() == [] and counts[-1] == 0


def test_status_label_is_icon_plus_text() -> None:
    assert status_label(Status.FAIL).startswith("✗") and status_label(Status.PASS) == "✓ 양호"
    assert status_label(Status.UNKNOWN).startswith("?") and status_label(Status.ERROR).startswith("!")
