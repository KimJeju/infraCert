"""자산 트리 모델 + 상태 배지 델리게이트.

트리: 고객사(project) > 분류(group) > 호스트. 호스트 행에 연결/실행 상태 배지와
마지막 진단 요약(취약/수동/오류)을 회색으로 병기한다(§1.1). 배지는 델리게이트가 직접 그린다.
"""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from infraguard.assets import query
from infraguard.assets.models import Host
from infraguard.ui.theme import BADGE

HOST_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 1
STATE_ROLE = int(Qt.ItemDataRole.UserRole) + 2
SUMMARY_ROLE = int(Qt.ItemDataRole.UserRole) + 3


class AssetTreeModel(QStandardItemModel):
    def rebuild(self, hosts: list[Host], filter_text: str = "") -> None:
        self.clear()
        q = query.parse(filter_text)
        root = self.invisibleRootItem()
        projects: dict[str, QStandardItem] = {}
        groups: dict[tuple[str, str], QStandardItem] = {}

        for h in sorted(hosts, key=lambda x: (x.project, x.group, x.label)):
            if not q.matches(h):
                continue
            if h.project not in projects:
                p = QStandardItem(h.project)
                p.setEditable(False)
                projects[h.project] = p
                root.appendRow(p)
            gk = (h.project, h.group)
            if gk not in groups:
                g = QStandardItem(h.group)
                g.setEditable(False)
                groups[gk] = g
                projects[h.project].appendRow(g)

            item = QStandardItem(h.label)
            item.setEditable(False)
            item.setData(h.host_id, HOST_ID_ROLE)
            item.setData("idle", STATE_ROLE)
            item.setData(_summary_str(h.last_summary), SUMMARY_ROLE)
            groups[gk].appendRow(item)

        # 프로젝트/그룹 노드에 개수 병기
        for name, p in projects.items():
            n = sum(_count(p.child(i)) for i in range(p.rowCount()))
            p.setText(f"{name} ({n})")
        for (_proj, grp), g in groups.items():
            g.setText(f"{grp} ({g.rowCount()})")

    def find_host_item(self, host_id: str) -> QStandardItem | None:
        def walk(it: QStandardItem):
            for i in range(it.rowCount()):
                c = it.child(i)
                if c.data(HOST_ID_ROLE) == host_id:
                    return c
                r = walk(c)
                if r:
                    return r
            return None
        return walk(self.invisibleRootItem())

    def set_state(self, host_id: str, state: str) -> None:
        it = self.find_host_item(host_id)
        if it:
            it.setData(state, STATE_ROLE)


def _count(item: QStandardItem) -> int:
    return item.rowCount() if item.rowCount() else 1


def _summary_str(summary: dict[str, int]) -> str:
    if not summary:
        return ""
    f = summary.get("FAIL", 0)
    u = summary.get("UNKNOWN", 0)
    e = summary.get("ERROR", 0)
    return f"{f}/{u}/{e}"


class StatusDelegate(QStyledItemDelegate):
    """호스트 행에 상태 배지(색 원)와 요약을 그린다."""

    DOT = 9

    def paint(self, painter, option, index: QModelIndex) -> None:  # noqa: N802
        state = index.data(STATE_ROLE)
        if state is None:
            super().paint(painter, option, index)
            return

        # 선택/호버 배경
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor("#1F6FEB"))
        elif option.state & QStyle.StateFlag.State_MouseOver:
            painter.fillRect(option.rect, QColor("#161B22"))

        painter.save()
        r = option.rect
        cy = r.center().y()
        dot_x = r.left() + 6
        painter.setBrush(QColor(BADGE.get(state, BADGE["idle"])))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(dot_x, cy - self.DOT // 2, self.DOT, self.DOT)

        # 이름
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        painter.setPen(QColor("white" if selected else "#C9D1D9"))
        name = index.data(Qt.ItemDataRole.DisplayRole) or ""
        text_x = dot_x + self.DOT + 6
        summary = index.data(SUMMARY_ROLE) or ""
        fm = painter.fontMetrics()
        sw = fm.horizontalAdvance(summary) + 8 if summary else 0
        name_rect = r.adjusted(text_x - r.left(), 0, -sw, 0)
        painter.drawText(name_rect, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft),
                         fm.elidedText(name, Qt.TextElideMode.ElideRight, name_rect.width()))
        # 요약 (회색)
        if summary:
            painter.setPen(QColor("#6E7681"))
            painter.drawText(r.adjusted(0, 0, -6, 0),
                             int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight), summary)
        painter.restore()

    def sizeHint(self, option, index):  # noqa: N802
        s = super().sizeHint(option, index)
        s.setHeight(max(s.height(), 24))
        if index.data(STATE_ROLE) is not None:      # 배지 + 이름 + 요약이 겹치지 않게 폭에 요약도 포함
            fm = option.fontMetrics
            summary = index.data(SUMMARY_ROLE) or ""
            s.setWidth(s.width() + self.DOT + 6 + (fm.horizontalAdvance(summary) + 14 if summary else 0))
        return s
