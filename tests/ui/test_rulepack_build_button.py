"""룰팩 탭 '선택 항목으로 룰팩 zip 만들기' — 체크한 항목이 그대로 builder 로 가고, 빈 선택은 거부된다."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPushButton

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from infraguard.rulepack import builder, loader  # noqa: E402
from infraguard.ui.pages.rulepack import ID_ROLE, RulePackPage  # noqa: E402

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


def test_button_emits_checked_selection(qtbot) -> None:  # noqa: ANN001
    page = RulePackPage()
    qtbot.addWidget(page)
    page.load(loader.load(PACK))
    got: list = []
    page.build_requested.connect(lambda b, n: got.append((b, n)))
    for it in page._iter_checkable():
        on = it.data(ID_ROLE) in ("aix-unix", "U-16")
        it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
    btn = next(b for b in page.findChildren(QPushButton) if "룰팩 zip" in b.text())
    qtbot.mouseClick(btn, Qt.MouseButton.LeftButton)
    assert got == [(["aix-unix"], ["U-16"])]


def test_builder_rejects_empty_selection(tmp_path: Path) -> None:
    with pytest.raises(builder.BuildError):
        builder.build(PACK, "x", tmp_path / "x.zip")
