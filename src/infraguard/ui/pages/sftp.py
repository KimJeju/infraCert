"""파일 브라우저(§8) — 로컬(workspace/) ↔ 원격 SFTP.

- 다운로드는 workspace/ 밖으로 못 나간다(Layout.contains).
- 원격 삭제는 확인 다이얼로그 필수, 파일만(디렉터리 X).
- 전송은 워커 스레드에서, 진행률 표시. SFTP 클라이언트는 스레드 안전이 아니므로
  세션 객체 하나가 큐 방식(queued slot)으로 작업을 직렬 처리한다.
"""

from __future__ import annotations

import posixpath
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.credentials.session import Credential
from infraguard.transport.ssh import SSHConnection
from infraguard.workspace.layout import Layout


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


class SftpSession(QObject):
    """워커 스레드. 슬롯은 queued 로 호출되어 자연히 직렬화된다."""

    listing = Signal(str, list)          # path, [(name, size, is_dir, mtime)]
    progress = Signal(int, int)
    done = Signal(str)
    error = Signal(str)
    connected = Signal()
    viewed = Signal(str, str)            # remote, local(받아 둔 사본)

    def __init__(self, host: Host, cred: Credential, approve, changed=None) -> None:  # noqa: ANN001
        self._changed = changed
        super().__init__()
        self._host, self._cred, self._approve = host, cred, approve
        self._conn: SSHConnection | None = None

    def _c(self) -> SSHConnection:
        if self._conn is None:
            raise RuntimeError("연결되지 않음")
        return self._conn

    @Slot()
    def connect_(self) -> None:
        from infraguard.ui.workers import build_connection
        try:
            self._conn = build_connection(self._host, self._cred, self._approve, self._changed)
            self._conn.connect()
            self.connected.emit()
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"연결 실패: {e}")

    @Slot(str)
    def list_dir(self, path: str) -> None:
        try:
            self.listing.emit(path, self._c().listdir_attr(path))
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"목록 실패 {path}: {e}")

    @Slot(str, str)
    def download(self, remote: str, local: str) -> None:
        try:
            self._c().download_progress(remote, Path(local), lambda a, b: self.progress.emit(a, b))
            self.done.emit(f"받기 완료: {Path(local).name}")
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"받기 실패: {e}")

    @Slot(str, str)
    def upload(self, local: str, remote: str) -> None:
        try:
            self._c().upload_progress(Path(local), remote, lambda a, b: self.progress.emit(a, b))
            self.done.emit(f"보내기 완료: {Path(local).name}")
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"보내기 실패: {e}")

    @Slot(str, str)
    def view(self, remote: str, local: str) -> None:
        """읽기 전용 보기용 사본. 2MB 넘으면 거부(뷰어는 설정 파일용)."""
        try:
            st = self._c()._sftp_client().stat(remote)  # noqa: SLF001
            if (st.st_size or 0) > 2 * 1024 * 1024:
                self.error.emit(f"보기 거부: {remote} 가 2MB 를 넘습니다(받기로 받으세요)")
                return
            self._c().download_progress(remote, Path(local), lambda a, b: self.progress.emit(a, b))
            self.viewed.emit(remote, local)
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"보기 실패: {e}")

    @Slot(str)
    def remove(self, remote: str) -> None:
        try:
            self._c().remove(remote)
            self.done.emit(f"삭제: {remote}")
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"삭제 실패: {e}")

    @Slot()
    def close(self) -> None:
        if self._conn:
            self._conn.close()


class _DropTree(QTreeWidget):
    """드래그앤드롭: 반대편 창에서 떨어뜨리면 dropped(names) 를 낸다. 실제 전송은 페이지가 확인 후 한다."""

    dropped = Signal(list)

    def __init__(self, tag: str) -> None:
        super().__init__()
        self.tag = tag
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QTreeWidget.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)

    def mimeData(self, items):  # noqa: N802,ANN001,ANN201
        from PySide6.QtCore import QMimeData
        md = QMimeData()
        names = [it.data(0, Qt.ItemDataRole.UserRole)[0] for it in items
                 if it.data(0, Qt.ItemDataRole.UserRole) and not it.data(0, Qt.ItemDataRole.UserRole)[1]]
        md.setData("application/x-infraguard-files", ("\n".join(names)).encode())
        md.setData("application/x-infraguard-src", self.tag.encode())
        return md

    def dragEnterEvent(self, e) -> None:  # noqa: N802,ANN001
        md = e.mimeData()
        if md.hasFormat("application/x-infraguard-files") and bytes(md.data("application/x-infraguard-src")).decode() != self.tag:
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragMoveEvent(self, e) -> None:  # noqa: N802,ANN001
        self.dragEnterEvent(e)

    def dropEvent(self, e) -> None:  # noqa: N802,ANN001
        md = e.mimeData()
        if md.hasFormat("application/x-infraguard-files"):
            names = [n for n in bytes(md.data("application/x-infraguard-files")).decode().split("\n") if n]
            e.acceptProposedAction()
            self.dropped.emit(names)
        else:
            e.ignore()


class _Pane(QWidget):
    COLS = ["이름", "크기", "수정시간", "권한", "소유자"]

    def __init__(self, title: str, tag: str) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel(title)
        lay.addWidget(self.title)
        self.path = QLineEdit()
        self.path.setPlaceholderText("경로 입력 후 Enter")
        lay.addWidget(self.path)
        self.tree = _DropTree(tag)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        lay.addWidget(self.tree, 1)

    def fill(self, entries: list[tuple], parent: bool = True) -> None:
        from datetime import datetime
        self.tree.clear()
        if parent:
            up = QTreeWidgetItem(["📁 ..", "", "", "", ""])
            up.setData(0, Qt.ItemDataRole.UserRole, ("..", True))
            self.tree.addTopLevelItem(up)
        for ent in entries:
            name, size, is_dir, mtime = ent[0], ent[1], ent[2], ent[3]
            perm = ent[4] if len(ent) > 4 else ""
            owner = ent[5] if len(ent) > 5 else ""
            ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else ""
            it = QTreeWidgetItem([("📁 " if is_dir else "📄 ") + name, "" if is_dir else _human(size), ts, perm, owner])
            it.setData(0, Qt.ItemDataRole.UserRole, (name, is_dir))
            self.tree.addTopLevelItem(it)

    def selected(self) -> list[tuple[str, bool]]:
        return [it.data(0, Qt.ItemDataRole.UserRole) for it in self.tree.selectedItems()]


class SftpPage(QWidget):
    def __init__(self, host: Host, cred: Credential, approve, layout: Layout,  # noqa: ANN001
                 start_path: str | None = None, changed=None) -> None:  # noqa: ANN001
        super().__init__()
        self.host = host
        self._layout = layout
        self._remote_cwd = start_path or "/tmp"  # noqa: S108 - 원격 시작 경로(사용자가 바꿈)
        self._local_cwd = layout.root

        root = QVBoxLayout(self)
        panes = QHBoxLayout()
        self.local = _Pane("로컬 (workspace/)", "local")
        self.remote = _Pane(f"원격 {host.label}", "remote")
        self.local.tree.dropped.connect(self._download_names)      # 원격 → 로컬 드롭
        self.remote.tree.dropped.connect(self._upload_names)       # 로컬 → 원격 드롭
        self.local.path.returnPressed.connect(lambda: self._cd_local(Path(self.local.path.text())))
        self.remote.path.returnPressed.connect(lambda: self._cd_remote(self.remote.path.text()))
        self.local.tree.itemDoubleClicked.connect(self._local_dbl)
        self.remote.tree.itemDoubleClicked.connect(self._remote_dbl)
        panes.addWidget(self.local, 1)
        panes.addWidget(self.remote, 1)
        root.addLayout(panes, 1)

        bar = QHBoxLayout()
        get = QPushButton("◀ 받기")
        put = QPushButton("보내기 ▶")
        view = QPushButton("보기(읽기 전용)")
        view.setToolTip("원격 파일을 workspace/tmp 로 받아 읽기 전용으로 연다. 설정 변경은 지원하지 않는다(제품 철학)")
        view.clicked.connect(self._view_selected)
        refresh = QPushButton("새로고침")
        delete = QPushButton("원격 삭제")
        delete.setObjectName("danger")
        get.clicked.connect(self._download)
        put.clicked.connect(self._upload)
        refresh.clicked.connect(self._refresh)
        delete.clicked.connect(self._delete)
        for b in (get, put, view, refresh, delete):
            bar.addWidget(b)
        bar.addStretch(1)
        self.prog = QProgressBar()
        self.prog.setMaximumWidth(220)
        self.prog.setVisible(False)
        bar.addWidget(self.prog)
        self.status = QLabel("연결 중…")
        self.status.setObjectName("muted")
        bar.addWidget(self.status)
        root.addLayout(bar)

        self._thread = QThread()
        self._s = SftpSession(host, cred, approve, changed)
        self._s.moveToThread(self._thread)
        self._thread.started.connect(self._s.connect_)
        self._s.connected.connect(self._on_connected)
        self._s.listing.connect(self._on_listing)
        self._s.progress.connect(self._on_progress)
        self._s.done.connect(self._on_done)
        self._s.error.connect(self._on_error)
        self._s.viewed.connect(self._on_viewed)
        self._thread.start()
        self._cd_local(self._local_cwd)

    def open_on_connect(self, remote_file: str) -> None:
        """연결되면 이 파일을 읽기 전용 뷰어로 연다(결과 탭 '파일 열기')."""
        self._open_after = remote_file

    # --- 로컬 ---
    def _cd_local(self, p: Path) -> None:
        p = p.resolve()
        if not self._layout.contains(p) or not p.is_dir():
            self._on_error("로컬 경로는 workspace/ 안이어야 합니다")
            return
        self._local_cwd = p
        self.local.path.setText(str(p))
        entries = []
        for c in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            st = c.stat()
            entries.append((c.name, st.st_size if c.is_file() else 0, c.is_dir(), int(st.st_mtime), "", ""))
        self.local.fill(entries, parent=(p != self._layout.root))

    def _local_dbl(self, it: QTreeWidgetItem) -> None:
        name, is_dir = it.data(0, Qt.ItemDataRole.UserRole)
        if is_dir:
            self._cd_local(self._local_cwd.parent if name == ".." else self._local_cwd / name)

    # --- 원격 ---
    def _on_connected(self) -> None:
        self.status.setText("연결됨")
        self._cd_remote(self._remote_cwd)
        f = getattr(self, "_open_after", None)
        if f:
            self._open_after = None
            self.view_remote(f)

    def _cd_remote(self, path: str) -> None:
        self._remote_cwd = posixpath.normpath(path) or "/"
        self.remote.path.setText(self._remote_cwd)
        self._s.list_dir(self._remote_cwd) if QThread.currentThread() is self._thread else \
            self._invoke("list_dir", self._remote_cwd)

    def _invoke(self, slot: str, *args) -> None:  # noqa: ANN002
        from PySide6.QtCore import Q_ARG, QMetaObject
        QMetaObject.invokeMethod(self._s, slot, Qt.ConnectionType.QueuedConnection,
                                 *[Q_ARG(str, a) for a in args])

    def _on_listing(self, path: str, entries: list) -> None:
        if path == self._remote_cwd:
            self.remote.fill(entries, parent=(path != "/"))

    def _remote_dbl(self, it: QTreeWidgetItem) -> None:
        name, is_dir = it.data(0, Qt.ItemDataRole.UserRole)
        if is_dir:
            self._cd_remote(posixpath.dirname(self._remote_cwd) if name == ".."
                            else posixpath.join(self._remote_cwd, name))
        else:
            self.view_remote(posixpath.join(self._remote_cwd, name))      # 더블클릭 = 읽기 전용 보기

    # --- 읽기 전용 뷰어 ---
    def view_remote(self, remote: str) -> None:
        local = (self._layout.tmp / "view" / Path(remote).name).resolve()
        if not self._layout.contains(local):
            self._on_error("뷰어 경로 오류")
            return
        local.parent.mkdir(parents=True, exist_ok=True)
        self.prog.setVisible(True)
        self._invoke("view", remote, str(local))

    def _view_selected(self) -> None:
        for n, d in self.remote.selected():
            if not d and n != "..":
                self.view_remote(posixpath.join(self._remote_cwd, n))
                return

    def _on_viewed(self, remote: str, local: str) -> None:
        from infraguard.ui.file_viewer import FileViewerDialog
        self.prog.setVisible(False)
        self.status.setText(f"보기: {remote}")
        FileViewerDialog(remote, Path(local), parent=self).show()

    # --- 드래그앤드롭 ---
    def _download_names(self, names: list[str]) -> None:
        for n in names:
            local = (self._local_cwd / n).resolve()
            if not self._layout.contains(local):
                self._on_error("workspace/ 밖으로는 받을 수 없습니다")
                return
            self.prog.setVisible(True)
            self._invoke("download", posixpath.join(self._remote_cwd, n), str(local))

    def _upload_names(self, names: list[str]) -> None:
        if not names or not self._confirm_upload(names):
            return
        for n in names:
            self.prog.setVisible(True)
            self._invoke("upload", str(self._local_cwd / n), posixpath.join(self._remote_cwd, n))

    def _confirm_upload(self, names: list[str]) -> bool:
        """업로드는 원격 잔류물이 된다 — 진단 스크립트 업로드(격리 디렉터리·자동 삭제)와 달리 사용자 책임."""
        return QMessageBox.question(
            self, "원격 업로드 확인",
            f"{self.host.label}:{self._remote_cwd} 에 파일 {len(names)}개를 올립니다:\n" + "\n".join(names[:8])
            + ("\n…" if len(names) > 8 else "")
            + "\n\n올린 파일은 InfraGuard 가 지우지 않습니다(원격 잔류물). 계속할까요?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes

    # --- 전송 ---
    def _download(self) -> None:
        files = [n for n, d in self.remote.selected() if not d and n != ".."]
        if not files:
            return
        for n in files:
            local = (self._local_cwd / n).resolve()
            if not self._layout.contains(local):
                self._on_error("workspace/ 밖으로는 받을 수 없습니다")
                return
            self.prog.setVisible(True)
            self._invoke("download", posixpath.join(self._remote_cwd, n), str(local))

    def _upload(self) -> None:
        self._upload_names([n for n, d in self.local.selected() if not d and n != ".."])

    def _delete(self) -> None:
        files = [n for n, d in self.remote.selected() if not d and n != ".."]
        if not files:
            return
        if QMessageBox.question(
            self, "원격 삭제", f"원격 파일 {len(files)}개를 삭제합니다:\n" + "\n".join(files)
        ) != QMessageBox.StandardButton.Yes:
            return
        for n in files:
            self._invoke("remove", posixpath.join(self._remote_cwd, n))

    def _refresh(self) -> None:
        self._cd_local(self._local_cwd)
        self._cd_remote(self._remote_cwd)

    def _on_progress(self, a: int, b: int) -> None:
        self.prog.setMaximum(max(1, b))
        self.prog.setValue(a)

    def _on_done(self, msg: str) -> None:
        self.status.setText(msg)
        self.prog.setVisible(False)
        self._refresh()

    def _on_error(self, msg: str) -> None:
        self.status.setText(f"✕ {msg}")
        self.status.setStyleSheet("color:#F85149")
        self.prog.setVisible(False)

    def shutdown(self) -> None:
        self._invoke("close")
        self._thread.quit()
        self._thread.wait(3000)
