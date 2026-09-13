"""세션 탭 컨테이너 — 터미널/SFTP 화면. 탭 닫기, 상태 점, (터미널) '선택 탭 동시 입력'."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QTabWidget, QVBoxLayout, QWidget

TAB_STATE = {"connecting": ("●", "#D29922"), "connected": ("●", "#2EA043"), "idle": ("●", "#8B949E"),
             "closed": ("○", "#6E7681"), "error": ("●", "#F85149")}


class SessionTabs(QWidget):
    """kind: 'terminal' | 'sftp'. close_requested(page) 로 메인윈도가 세션을 정리한다."""

    close_requested = Signal(object)
    count_changed = Signal(int)

    def __init__(self, kind: str, empty_text: str) -> None:
        super().__init__()
        self.kind = kind
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(12, 6, 12, 6)
        self.title = QLabel("터미널 세션" if kind == "terminal" else "SFTP 세션")
        self.title.setObjectName("h2")
        head.addWidget(self.title)
        head.addStretch(1)
        self.multi = QCheckBox("선택 탭 동시 입력")
        self.multi.setToolTip("체크한 터미널 탭 전부에 같은 키 입력을 보낸다(실수 위험 — 대상 수를 항상 표시)")
        self.multi_n = QLabel("")
        self.multi_n.setObjectName("muted")
        if kind == "terminal":
            head.addWidget(self.multi)
            head.addWidget(self.multi_n)
        else:
            self.multi.hide()
        lay.addLayout(head)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(lambda i: self.close_requested.emit(self.tabs.widget(i)))
        lay.addWidget(self.tabs, 1)
        self.empty = QLabel(empty_text)
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.empty, 1)
        self._sync()

    def _sync(self) -> None:
        n = self.tabs.count()
        self.tabs.setVisible(n > 0)
        self.empty.setVisible(n == 0)
        self.count_changed.emit(n)

    def add(self, page: QWidget, label: str) -> int:
        i = self.tabs.addTab(page, label)
        self.tabs.setCurrentIndex(i)
        self._sync()
        return i

    def remove(self, page: QWidget) -> None:
        i = self.tabs.indexOf(page)
        if i >= 0:
            self.tabs.removeTab(i)
        self._sync()

    def pages(self) -> list[QWidget]:
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def set_state(self, page: QWidget, state: str, label: str) -> None:
        i = self.tabs.indexOf(page)
        if i < 0:
            return
        dot, color = TAB_STATE.get(state, ("●", "#8B949E"))
        self.tabs.setTabText(i, f"{dot} {label}")
        self.tabs.tabBar().setTabTextColor(i, QColor(color))

    def set_multi_count(self, n: int) -> None:
        self.multi_n.setText(f"대상 {n}개 탭" if n else "")
