"""자산 화면 — Asset Explorer(왼쪽) + Host Detail(작업영역).

사이드바에 몰려 있던 탐색·상세·액션·관리를 여기로 옮겼다. 탐색은 왼쪽만, 상세와 액션은 오른쪽.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.core.status import Status
from infraguard.ui.models_qt import AssetTreeModel, StatusDelegate
from infraguard.ui.theme import STATUS_FG, STATUS_ICON

ACTIONS = (("scan", "▶ 진단"), ("terminal", "터미널"), ("sftp", "SFTP"), ("discovery", "Discovery"),
           ("results", "결과"), ("edit", "편집"))


class HostDetail(QWidget):
    action = Signal(str, str)   # action, host_id

    def __init__(self) -> None:
        super().__init__()
        self._host_id: str | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)
        self.title = QLabel("호스트를 선택하세요")
        self.title.setObjectName("h1")
        self.title.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.title)
        self.sub = QLabel("")
        self.sub.setObjectName("muted")
        lay.addWidget(self.sub)
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(4)
        self._rows: dict[str, QLabel] = {}
        for i, key in enumerate(("주소", "OS", "환경 / 중요도", "역할 / 담당", "태그", "파라미터", "Profile", "Last Scan")):
            k = QLabel(key)
            k.setObjectName("muted")
            v = QLabel("-")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(k, i, 0)
            grid.addWidget(v, i, 1)
            self._rows[key] = v
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)
        self.summary = QLabel("")
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        self.summary.setStyleSheet("font-size:14px")
        lay.addWidget(self.summary)
        row = QHBoxLayout()
        row.setSpacing(6)
        self._btns: dict[str, QPushButton] = {}
        for key, label in ACTIONS:
            b = QPushButton(label)
            if key == "scan":
                b.setObjectName("primary")
            b.setEnabled(False)
            b.clicked.connect(lambda _c=False, k=key: self._emit(k))
            row.addWidget(b)
            self._btns[key] = b
        row.addStretch(1)
        lay.addLayout(row)
        self.discovered = QLabel("")
        self.discovered.setObjectName("muted")
        self.discovered.setWordWrap(True)
        lay.addWidget(self.discovered)
        self.recent_vulns = QLabel("")
        self.recent_vulns.setWordWrap(True)
        self.recent_vulns.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.recent_vulns)
        lay.addStretch(1)

    def _emit(self, key: str) -> None:
        if self._host_id:
            self.action.emit(key, self._host_id)

    def clear(self, n_selected: int = 0) -> None:
        self._host_id = None
        self.title.setText(f"{n_selected}대 선택됨 — [진단] 은 선택 전체" if n_selected > 1 else "호스트를 선택하세요")
        self.sub.setText("")
        for v in self._rows.values():
            v.setText("-")
        self.summary.setText("")
        self.discovered.setText("")
        self.recent_vulns.setText("")
        for k, b in self._btns.items():
            b.setEnabled(k == "scan" and n_selected > 1)

    def show_host(self, host: Host, *, os_text: str | None = None, profile: str | None = None,
                  last_at: datetime | str | None = None, summary: dict[str, int] | None = None,
                  recent_vulns: list[str] | None = None) -> None:
        self._host_id = host.host_id
        self.title.setText(f"{host.label} <span style='color:#7D8794;font-weight:400;font-size:12px'>"
                           f"&nbsp; {host.project} / {host.group}</span>")
        self.sub.setText(" · ".join(x for x in (host.platform, host.environment, host.criticality, host.role) if x))
        self._rows["주소"].setText(f"{host.address}:{host.port}  ({host.username}, {host.auth_kind})"
                                 + (f"  via {host.bastion_host}" if host.use_bastion and host.bastion_host else ""))
        self._rows["OS"].setText(os_text or host.platform)
        self._rows["환경 / 중요도"].setText(f"{host.environment or '-'} / {host.criticality or '-'}")
        self._rows["역할 / 담당"].setText(f"{host.role or '-'} / {host.owner or '-'}")
        self._rows["태그"].setText(", ".join(host.tags) or "-")
        self._rows["파라미터"].setText(", ".join(f"{k}={v}" for k, v in host.params.items()) or "-")
        self._rows["Profile"].setText(profile or "-")
        if isinstance(last_at, datetime):
            last_at = last_at.strftime("%Y-%m-%d %H:%M")
        self._rows["Last Scan"].setText(str(last_at) if last_at else "진단 이력 없음")
        s = summary or host.last_summary or {}
        if s:
            parts = [f"<span style='color:{STATUS_FG[st]}'>{STATUS_ICON[st]} {name} {s.get(st.value, 0)}</span>"
                     for st, name in ((Status.PASS, "GOOD"), (Status.FAIL, "VULN"), (Status.UNKNOWN, "MANUAL"),
                                      (Status.ERROR, "ERROR"))]
            self.summary.setText(" &nbsp;&nbsp; ".join(parts))
        else:
            self.summary.setText("")
        d = host.discovered or {}
        if d:
            ports = ", ".join(f"{p} {n}" for p, n in sorted(d.get("ports", {}).items(), key=lambda kv: int(kv[0])))
            self.discovered.setText("Discovery: " + (ports or "열린 포트 없음")
                                    + (f" · {d.get('os')}" if d.get("os") else "")
                                    + (f" · 서비스 {', '.join(d.get('services', []))}" if d.get("services") else ""))
        else:
            self.discovered.setText("Discovery 미실행 — [Discovery] 로 포트·서비스·추천 프로파일을 확인")
        self.recent_vulns.setText(("최근 취약: " + ", ".join(recent_vulns[:10])) if recent_vulns else "")
        for b in self._btns.values():
            b.setEnabled(True)
        self._btns["results"].setEnabled(bool(host.last_scan_id))
        self._btns["terminal"].setEnabled(host.platform not in ("windows", "pc"))
        self._btns["sftp"].setEnabled(host.platform not in ("windows", "pc", "network"))


class AssetsPage(QWidget):
    add_requested = Signal()
    import_requested = Signal()
    filter_changed = Signal(str)
    group_apply = Signal(str)          # query
    group_save = Signal()
    group_delete = Signal(str)         # query
    context_menu = Signal(object)      # QPoint (tree viewport)
    edit_requested = Signal(object)    # QModelIndex

    def __init__(self) -> None:
        super().__init__()
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        side = QWidget()
        side.setObjectName("sidebar")
        sl = QVBoxLayout(side)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(8)
        st = QLabel("ASSETS")
        st.setObjectName("sidebar-title")
        sl.addWidget(st)
        self.filter = QLineEdit()
        self.filter.setClearButtonEnabled(True)
        self.filter.setPlaceholderText("검색 / 쿼리: os=linux env=PROD crit=CRITICAL")
        self.filter.setToolTip("공백 = AND. key=a,b = OR. key!=v 제외. 키: os env crit role tag group project owner name addr\n"
                               "그 외 단어는 이름·주소·그룹·고객사 부분일치")
        self.filter.textChanged.connect(self.filter_changed)
        sl.addWidget(self.filter)
        grow = QHBoxLayout()
        self.groups = QComboBox()
        self.groups.setToolTip("동적 그룹 — 저장한 쿼리. 새 자산이 조건에 맞으면 자동으로 포함된다")
        self.groups.activated.connect(lambda _i: self.group_apply.emit(self.groups.currentData() or ""))
        grow.addWidget(self.groups, 1)
        gsave = QPushButton("저장")
        gsave.setToolTip("현재 쿼리를 동적 그룹으로 저장")
        gsave.clicked.connect(self.group_save)
        gdel = QPushButton("×")
        gdel.setFixedWidth(28)
        gdel.clicked.connect(lambda: self.group_delete.emit(self.groups.currentData() or ""))
        grow.addWidget(gsave)
        grow.addWidget(gdel)
        sl.addLayout(grow)
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setHorizontalScrollMode(QTreeView.ScrollMode.ScrollPerPixel)
        self.tree.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)
        self.model = AssetTreeModel()
        self.tree.setModel(self.model)
        self.tree.setItemDelegate(StatusDelegate())
        self.tree.doubleClicked.connect(lambda idx: self.edit_requested.emit(idx))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(lambda pos: self.context_menu.emit(pos))
        sl.addWidget(self.tree, 1)
        brow = QHBoxLayout()
        add = QPushButton("+ 자산 추가")
        imp = QPushButton("가져오기")
        add.clicked.connect(self.add_requested)
        imp.clicked.connect(self.import_requested)
        brow.addWidget(add)
        brow.addWidget(imp)
        sl.addLayout(brow)
        split.addWidget(side)
        self.detail = HostDetail()
        split.addWidget(self.detail)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([300, 900])
        split.setHandleWidth(1)
        outer.addWidget(split)

    def set_groups(self, groups: list[dict]) -> None:
        self.groups.blockSignals(True)
        self.groups.clear()
        self.groups.addItem("동적 그룹…", "")
        for g in groups:
            self.groups.addItem(f"{g.get('name')}  ({g.get('query')})", g.get("query", ""))
        self.groups.blockSignals(False)
