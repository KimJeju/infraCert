"""사이드바 다건 선택 — 고객사/분류 노드를 고르면 하위 호스트 전부, '모든 호스트 진단'은 전체."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QItemSelectionModel  # noqa: E402

from infraguard.assets.models import Host  # noqa: E402
from infraguard.ui.models_qt import HOST_ID_ROLE, AssetTreeModel  # noqa: E402


def _hosts() -> list[Host]:
    return [
        Host(host_id="a1", name="a1", address="1.1.1.1", project="A사", group="서버"),
        Host(host_id="a2", name="a2", address="1.1.1.2", project="A사", group="서버"),
        Host(host_id="a3", name="a3", address="1.1.1.3", project="A사", group="DB"),
        Host(host_id="b1", name="b1", address="2.2.2.1", project="B사", group="서버"),
    ]


class _Assets:
    def __init__(self, hosts: list[Host]) -> None:
        self._h = {h.host_id: h for h in hosts}

    def get(self, hid: str) -> Host | None:
        return self._h.get(hid)


def _selected(window_cls, tree, model, assets):  # noqa: ANN001,ANN201
    """MainWindow._selected_hosts 를 최소 객체로 흉내(창 전체를 띄우지 않고 로직만)."""
    class W:
        pass
    w = W()
    w.tree = tree
    w.ctx = type("C", (), {"assets": assets})()
    return window_cls._selected_hosts(w)


def test_group_selection_expands_to_children(qtbot) -> None:  # noqa: ANN001
    from PySide6.QtWidgets import QTreeView  # noqa: PLC0415

    from infraguard.ui.main_window import MainWindow  # noqa: PLC0415

    hosts = _hosts()
    model = AssetTreeModel()
    model.rebuild(hosts)
    tree = QTreeView()
    qtbot.addWidget(tree)
    tree.setModel(model)
    tree.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)
    assets = _Assets(hosts)

    # 최상위(A사) 하나 선택 → a1 a2 a3
    a = model.index(0, 0)
    assert not a.data(HOST_ID_ROLE)
    tree.selectionModel().select(a, QItemSelectionModel.SelectionFlag.ClearAndSelect)
    got = [h.host_id for h in _selected(MainWindow, tree, model, assets)]
    assert sorted(got) == ["a1", "a2", "a3"]        # 분류(DB/서버) 정렬 순서는 관심 밖, 집합만

    # 그룹(A사/DB) + 호스트(b1) 섞어 선택, 중복 없음
    db = next(model.index(r, 0, a) for r in range(model.rowCount(a)) if str(model.index(r, 0, a).data()).startswith("DB"))
    b = model.index(1, 0)
    b1 = model.index(0, 0, model.index(0, 0, b))
    sm = tree.selectionModel()
    sm.select(db, QItemSelectionModel.SelectionFlag.ClearAndSelect)
    sm.select(b1, QItemSelectionModel.SelectionFlag.Select)
    sm.select(model.index(0, 0, db), QItemSelectionModel.SelectionFlag.Select)   # a3 를 한 번 더
    got = [h.host_id for h in _selected(MainWindow, tree, model, assets)]
    assert sorted(got) == ["a3", "b1"] and len(got) == 2

    tree.selectAll()
    assert sorted(h.host_id for h in _selected(MainWindow, tree, model, assets)) == ["a1", "a2", "a3", "b1"]
