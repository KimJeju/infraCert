"""자체 타이틀바 — OS 창 테두리 없이(FramelessWindowHint) 앱 이름·창 버튼을 앱 스타일로.

드래그 이동·더블클릭 최대화는 Qt 의 startSystemMove 로 OS 에 맡긴다(스냅·모니터 이동이 그대로 된다).
가장자리 리사이즈는 MainWindow 가 contentsMargins 띠에서 startSystemResize 로 처리한다.
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget


class TitleBar(QWidget):
    HEIGHT = 32

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("titlebar")
        self.setFixedHeight(self.HEIGHT)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 0, 0)
        lay.setSpacing(0)
        self.mark = QLabel("◆")
        self.mark.setObjectName("title-mark")
        self.title = QLabel(title)
        self.title.setObjectName("title-text")
        self.sub = QLabel("")
        self.sub.setObjectName("title-sub")
        lay.addWidget(self.mark)
        lay.addSpacing(8)
        lay.addWidget(self.title)
        lay.addSpacing(12)
        lay.addWidget(self.sub)
        lay.addStretch(1)
        self.btn_min = self._btn("—", "최소화")
        self.btn_max = self._btn("□", "최대화/복원")
        self.btn_close = self._btn("×", "닫기")     # U+00D7 — Malgun Gothic 에 있는 글리프(✕ 는 □ 로 깨진다)
        self.btn_close.setObjectName("title-close")
        for b in (self.btn_min, self.btn_max, self.btn_close):
            lay.addWidget(b)
        self.btn_min.clicked.connect(lambda: self.window().showMinimized())
        self.btn_max.clicked.connect(self._toggle_max)
        self.btn_close.clicked.connect(lambda: self.window().close())

    def _btn(self, text: str, tip: str) -> QToolButton:
        b = QToolButton(self)
        b.setObjectName("title-btn")
        b.setText(text)
        b.setToolTip(tip)
        b.setFixedSize(46, self.HEIGHT)
        b.setCursor(Qt.CursorShape.ArrowCursor)
        return b

    def set_subtitle(self, text: str) -> None:
        self.sub.setText(text)

    def _toggle_max(self) -> None:
        w = self.window()
        if w.isMaximized():
            w.showNormal()
        else:
            w.showMaximized()

    # ------------------------------------------------------------ 드래그/더블클릭
    def mousePressEvent(self, e) -> None:  # noqa: N802,ANN001
        if e.button() == Qt.MouseButton.LeftButton and self.childAt(e.position().toPoint()) not in (
                self.btn_min, self.btn_max, self.btn_close):
            wh = self.window().windowHandle()
            if wh is not None:
                wh.startSystemMove()
                return
        super().mousePressEvent(e)

    def mouseDoubleClickEvent(self, e) -> None:  # noqa: N802,ANN001
        if e.button() == Qt.MouseButton.LeftButton:
            self._toggle_max()


def edges_at(pos: QPoint, w: int, h: int, margin: int) -> Qt.Edge:
    """창 안 좌표가 어느 가장자리 띠에 있는지(리사이즈 방향). 띠 밖이면 빈 플래그."""
    edges = Qt.Edge(0)
    if pos.x() <= margin:
        edges |= Qt.Edge.LeftEdge
    elif pos.x() >= w - margin:
        edges |= Qt.Edge.RightEdge
    if pos.y() <= margin:
        edges |= Qt.Edge.TopEdge
    elif pos.y() >= h - margin:
        edges |= Qt.Edge.BottomEdge
    return edges


CURSORS = {
    Qt.Edge.LeftEdge: Qt.CursorShape.SizeHorCursor, Qt.Edge.RightEdge: Qt.CursorShape.SizeHorCursor,
    Qt.Edge.TopEdge: Qt.CursorShape.SizeVerCursor, Qt.Edge.BottomEdge: Qt.CursorShape.SizeVerCursor,
    Qt.Edge.TopEdge | Qt.Edge.LeftEdge: Qt.CursorShape.SizeFDiagCursor,
    Qt.Edge.BottomEdge | Qt.Edge.RightEdge: Qt.CursorShape.SizeFDiagCursor,
    Qt.Edge.TopEdge | Qt.Edge.RightEdge: Qt.CursorShape.SizeBDiagCursor,
    Qt.Edge.BottomEdge | Qt.Edge.LeftEdge: Qt.CursorShape.SizeBDiagCursor,
}
