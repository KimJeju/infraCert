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

    def __init__(self, host: Host, cred: Credential, approve) -> None:  # noqa: ANN001
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
            self._conn = build_connection(self._host, self._cred, self._approve)
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


class _Pane(QWidget):
    def __init__(self, title: str) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel(title)
        lay.addWidget(self.title)
        self.path = QLineEdit()
        lay.addWidget(self.path)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["이름", "크기"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def fill(self, entries: list[tuple[str, int, bool, int]], parent: bool = True) -> None:
        self.tree.clear()
        if parent:
            up = QTreeWidgetItem(["📁 ..", ""])
            up.setData(0, Qt.ItemDataRole.UserRole, ("..", True))
            self.tree.addTopLevelItem(up)
        for name, size, is_dir, _m in entries:
            it = QTreeWidgetItem([("📁 " if is_dir else "📄 ") + name, "" if is_dir else _human(size)])
            it.setData(0, Qt.ItemDataRole.UserRole, (name, is_dir))
            self.tree.addTopLevelItem(it)

    def selected(self) -> list[tuple[str, bool]]:
        return [it.data(0, Qt.ItemDataRole.UserRole) for it in self.tree.selectedItems()]


class SftpPage(QWidget):
    def __init__(self, host: Host, cred: Credential, approve, layout: Layout) -> None:  # noqa: ANN001
        super().__init__()
        self.host = host
        self._layout = layout
        self._remote_cwd = "/tmp"  # noqa: S108 - 원격 시작 경로(사용자가 바꿈)
        self._local_cwd = layout.root

        root = QVBoxLayout(self)
        panes = QHBoxLayout()
        self.local = _Pane("로컬 (workspace/)")
        self.remote = _Pane(f"원격 {host.label}")
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
        refresh = QPushButton("새로고침")
        delete = QPushButton("원격 삭제")
        delete.setObjectName("danger")
        get.clicked.connect(self._download)
        put.clicked.connect(self._upload)
        refresh.clicked.connect(self._refresh)
        delete.clicked.connect(self._delete)
        for b in (get, put, refresh, delete):
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
        self._s = SftpSession(host, cred, approve)
        self._s.moveToThread(self._thread)
        self._thread.started.connect(self._s.connect_)
        self._s.connected.connect(self._on_connected)
        self._s.listing.connect(self._on_listing)
        self._s.progress.connect(self._on_progress)
        self._s.done.connect(self._on_done)
        self._s.error.connect(self._on_error)
        self._thread.start()
        self._cd_local(self._local_cwd)

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
            entries.append((c.name, c.stat().st_size if c.is_file() else 0, c.is_dir(), 0))
        self.local.fill(entries, parent=(p != self._layout.root))

    def _local_dbl(self, it: QTreeWidgetItem) -> None:
        name, is_dir = it.data(0, Qt.ItemDataRole.UserRole)
        if is_dir:
            self._cd_local(self._local_cwd.parent if name == ".." else self._local_cwd / name)

    # --- 원격 ---
    def _on_connected(self) -> None:
        self.status.setText("연결됨")
        self._cd_remote(self._remote_cwd)

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
        files = [n for n, d in self.local.selected() if not d and n != ".."]
        for n in files:
            self.prog.setVisible(True)
            self._invoke("upload", str(self._local_cwd / n), posixpath.join(self._remote_cwd, n))

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
