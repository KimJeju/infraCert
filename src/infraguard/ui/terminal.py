"""터미널 탭(§7) — pyte VT100 에뮬레이터 + QWidget 직접 페인팅.

구조:
    TerminalSession (워커 QThread)  connect → invoke_shell → 논블로킹 read 루프 → data(bytes) 시그널
    TerminalWidget  (UI 스레드)     pyte.HistoryScreen 갱신 → 변경 라인만 다시 그림 → 키입력 → VT 시퀀스
    TerminalRecorder (순수 파이썬)   입력·출력 기록 + 비밀번호 마스킹

워커는 위젯을 만지지 않는다. Secret 은 시그널에 실리지 않는다(세션 생성자 인자로 전달).
"""

from __future__ import annotations

import time
from pathlib import Path

import pyte
from PySide6.QtCore import QObject, QPoint, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontDatabase,
    QFontMetrics,
    QGuiApplication,
    QKeyEvent,
    QPainter,
)
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QMenu, QVBoxLayout, QWidget

from infraguard.assets.models import Host
from infraguard.audit.terminal_recorder import TerminalRecorder
from infraguard.credentials.session import Credential
from infraguard.transport.ssh import SSHConnection
from infraguard.ui.theme import BADGE

COLS_DEFAULT, ROWS_DEFAULT = 120, 32
HISTORY = 5000

# 16색 + default. 256/truecolor 은 pyte 가 hex 문자열로 준다.
_PALETTE = {
    "black": "#0D1117", "red": "#F85149", "green": "#3FB950", "brown": "#D29922",
    "blue": "#58A6FF", "magenta": "#BC8CFF", "cyan": "#39C5CF", "white": "#C9D1D9",
    "brightblack": "#6E7681", "brightred": "#FF7B72", "brightgreen": "#56D364",
    "brightyellow": "#E3B341", "brightblue": "#79C0FF", "brightmagenta": "#D2A8FF",
    "brightcyan": "#56D4DD", "brightwhite": "#F0F6FC",
}
_DEFAULT_FG, _DEFAULT_BG = "#C9D1D9", "#0D1117"


def _qcolor(name: str, default: str) -> QColor:
    if name == "default":
        return QColor(default)
    if name in _PALETTE:
        return QColor(_PALETTE[name])
    if len(name) == 6:                       # pyte truecolor/256 → "rrggbb"
        return QColor("#" + name)
    return QColor(default)


# ------------------------------------------------------------------ 워커
class TerminalSession(QObject):
    """SSH 대화형 셸. QThread 로 옮겨 read 루프를 돈다. 위젯 접근 금지."""

    connected = Signal()
    data = Signal(bytes)
    closed = Signal(str)
    error = Signal(str)

    def __init__(self, host: Host, cred: Credential, approve, cols: int, rows: int) -> None:  # noqa: ANN001
        super().__init__()
        self._host = host
        self._cred = cred
        self._approve = approve
        self._cols, self._rows = cols, rows
        self._conn: SSHConnection | None = None
        self._chan = None
        self._stop = False

    @Slot()
    def run(self) -> None:
        from infraguard.ui.workers import build_connection
        try:
            self._conn = build_connection(self._host, self._cred, self._approve)
            self._conn.connect()
            self._chan = self._conn.open_shell(self._cols, self._rows)
            self.connected.emit()
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"{type(e).__name__}: {e}")
            self._cleanup()
            return
        try:
            while not self._stop and self._chan is not None and not self._chan.closed:
                if self._chan.recv_ready():
                    b = self._chan.recv(65536)
                    if not b:
                        break
                    self.data.emit(b)
                elif self._chan.exit_status_ready():
                    break
                else:
                    time.sleep(0.01)
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"{type(e).__name__}: {e}")
        finally:
            self._cleanup()
            self.closed.emit("세션 종료")

    @Slot(bytes)
    def send(self, b: bytes) -> None:
        try:
            if self._chan is not None and not self._chan.closed:
                self._chan.sendall(b)
        except Exception as e:  # noqa: BLE001
            self.error.emit(f"send: {e}")

    @Slot(int, int)
    def resize(self, cols: int, rows: int) -> None:
        try:
            if self._chan is not None:
                self._chan.resize_pty(width=cols, height=rows)
        except Exception:  # noqa: BLE001,S110
            pass

    @Slot()
    def stop(self) -> None:
        self._stop = True

    def _cleanup(self) -> None:
        try:
            if self._chan is not None:
                self._chan.close()
        except Exception:  # noqa: BLE001,S110
            pass
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:  # noqa: BLE001,S110
            pass
        self._chan = None


# ------------------------------------------------------------------ 위젯
_KEYMAP = {
    Qt.Key.Key_Up: b"\x1b[A", Qt.Key.Key_Down: b"\x1b[B", Qt.Key.Key_Right: b"\x1b[C",
    Qt.Key.Key_Left: b"\x1b[D", Qt.Key.Key_Home: b"\x1b[H", Qt.Key.Key_End: b"\x1b[F",
    Qt.Key.Key_PageUp: b"\x1b[5~", Qt.Key.Key_PageDown: b"\x1b[6~", Qt.Key.Key_Insert: b"\x1b[2~",
    Qt.Key.Key_Delete: b"\x1b[3~", Qt.Key.Key_Tab: b"\t", Qt.Key.Key_Backspace: b"\x7f",
    Qt.Key.Key_Return: b"\r", Qt.Key.Key_Enter: b"\r", Qt.Key.Key_Escape: b"\x1b",
    Qt.Key.Key_F1: b"\x1bOP", Qt.Key.Key_F2: b"\x1bOQ", Qt.Key.Key_F3: b"\x1bOR", Qt.Key.Key_F4: b"\x1bOS",
    Qt.Key.Key_F5: b"\x1b[15~", Qt.Key.Key_F6: b"\x1b[17~", Qt.Key.Key_F7: b"\x1b[18~",
    Qt.Key.Key_F8: b"\x1b[19~", Qt.Key.Key_F9: b"\x1b[20~", Qt.Key.Key_F10: b"\x1b[21~",
    Qt.Key.Key_F11: b"\x1b[23~", Qt.Key.Key_F12: b"\x1b[24~",
}


def _mono_font(size: int = 10) -> QFont:
    fams = set(QFontDatabase.families())
    for name in ("D2Coding", "Consolas", "Courier New"):
        if name in fams:
            f = QFont(name, size)
            f.setStyleHint(QFont.StyleHint.Monospace)
            return f
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(size)
    return f


class TerminalWidget(QWidget):
    """QPlainTextEdit 이 아니라 QWidget + paintEvent 로 직접 그린다(셀 단위 색·커서·성능)."""

    input_bytes = Signal(bytes)       # 사용자 입력 → 세션(및 브로드캐스트)
    resized = Signal(int, int)        # cols, rows

    def __init__(self) -> None:
        super().__init__()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self.cols, self.rows = COLS_DEFAULT, ROWS_DEFAULT
        self.screen = pyte.HistoryScreen(self.cols, self.rows, history=HISTORY)
        self.screen.set_mode(pyte.modes.LNM)
        self.stream = pyte.ByteStream(self.screen)
        self._font_size = 10
        self._apply_font()
        self._cursor_on = True
        self._blink = QTimer(self)
        self._blink.timeout.connect(self._toggle_cursor)
        self._blink.start(500)
        self._sel_start: tuple[int, int] | None = None
        self._sel_end: tuple[int, int] | None = None
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

    # --- 글꼴/셀 ---
    def _apply_font(self) -> None:
        self._font = _mono_font(self._font_size)
        self.setFont(self._font)
        fm = QFontMetrics(self._font)
        self._cw = max(1, fm.horizontalAdvance("M"))
        self._cw_wide = max(self._cw, fm.horizontalAdvance("한"))
        self._ch = max(1, fm.height())
        self._asc = fm.ascent()
        self.update()

    def set_font_size(self, size: int) -> None:
        self._font_size = max(7, min(24, size))
        self._apply_font()
        self._recalc_size()

    # --- 데이터 ---
    @Slot(bytes)
    def feed(self, data: bytes) -> None:
        self.stream.feed(data)
        self.update()

    def _toggle_cursor(self) -> None:
        self._cursor_on = not self._cursor_on
        self.update(self._cell_rect(self.screen.cursor.x, self.screen.cursor.y))

    def _cell_rect(self, x: int, y: int):  # noqa: ANN202
        from PySide6.QtCore import QRect
        return QRect(x * self._cw, y * self._ch, self._cw * 2, self._ch)

    # --- 그리기 ---
    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(_DEFAULT_BG))
        p.setFont(self._font)
        buf = self.screen.buffer
        for y in range(self.rows):
            line = buf[y]
            x = 0
            px = 0
            while x < self.cols:
                ch = line[x]
                data = ch.data or " "
                wide = self._is_wide(data)
                w = self._cw_wide if wide else self._cw
                fg = _qcolor(ch.fg, _DEFAULT_FG)
                bg = _qcolor(ch.bg, _DEFAULT_BG)
                if ch.reverse:
                    fg, bg = bg, fg
                if self._in_selection(x, y):
                    bg = QColor("#1F6FEB")
                if bg.name() != _DEFAULT_BG.lower():
                    p.fillRect(px, y * self._ch, w, self._ch, bg)
                if data.strip():
                    f = QFont(self._font)
                    f.setBold(bool(ch.bold))
                    f.setItalic(bool(ch.italics))
                    f.setUnderline(bool(ch.underscore))
                    p.setFont(f)
                    p.setPen(fg)
                    p.drawText(px, y * self._ch + self._asc, data)
                px += w
                x += 2 if wide else 1
        # 커서
        if self._cursor_on and self.hasFocus():
            cx, cy = self.screen.cursor.x, self.screen.cursor.y
            p.fillRect(cx * self._cw, cy * self._ch, self._cw, self._ch, QColor(200, 200, 200, 160))
        p.end()
        self.screen.dirty.clear()

    @staticmethod
    def _is_wide(s: str) -> bool:
        return any(ord(c) > 0x2E7F and not (0xFF61 <= ord(c) <= 0xFF9F) for c in s)

    # --- 선택/복사 ---
    def _in_selection(self, x: int, y: int) -> bool:
        if not self._sel_start or not self._sel_end:
            return False
        (x0, y0), (x1, y1) = sorted([self._sel_start, self._sel_end], key=lambda t: (t[1], t[0]))
        if y0 == y1:
            return y == y0 and x0 <= x <= x1
        return (y == y0 and x >= x0) or (y0 < y < y1) or (y == y1 and x <= x1)

    def selected_text(self) -> str:
        if not self._sel_start or not self._sel_end:
            return ""
        (x0, y0), (x1, y1) = sorted([self._sel_start, self._sel_end], key=lambda t: (t[1], t[0]))
        out = []
        for y in range(y0, y1 + 1):
            line = self.screen.buffer[y]
            a = x0 if y == y0 else 0
            b = x1 if y == y1 else self.cols - 1
            out.append("".join(line[x].data or " " for x in range(a, b + 1)).rstrip())
        return "\n".join(out)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self._sel_start = self._sel_end = self._cell_at(e.position())
            self.update()
        self.setFocus()

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        if e.buttons() & Qt.MouseButton.LeftButton:
            self._sel_end = self._cell_at(e.position())
            self.update()

    def _cell_at(self, pos) -> tuple[int, int]:  # noqa: ANN001
        return (max(0, min(self.cols - 1, int(pos.x() // self._cw))),
                max(0, min(self.rows - 1, int(pos.y() // self._ch))))

    def copy_selection(self) -> None:
        t = self.selected_text()
        if t:
            QGuiApplication.clipboard().setText(t)

    def paste_clipboard(self) -> None:
        t = QGuiApplication.clipboard().text()
        if t:
            self.input_bytes.emit(t.replace("\r\n", "\n").replace("\n", "\r").encode("utf-8"))

    # --- 입력 ---
    def keyPressEvent(self, e: QKeyEvent) -> None:  # noqa: N802
        mods = e.modifiers()
        key = e.key()
        ctrl = bool(mods & Qt.KeyboardModifier.ControlModifier)
        shift = bool(mods & Qt.KeyboardModifier.ShiftModifier)
        alt = bool(mods & Qt.KeyboardModifier.AltModifier)

        if ctrl and shift and key == Qt.Key.Key_C:
            self.copy_selection()
            return
        if ctrl and shift and key == Qt.Key.Key_V:
            self.paste_clipboard()
            return
        if shift and key == Qt.Key.Key_PageUp:
            self.screen.prev_page()
            self.update()
            return
        if shift and key == Qt.Key.Key_PageDown:
            self.screen.next_page()
            self.update()
            return

        out: bytes | None = None
        if key in _KEYMAP:
            out = _KEYMAP[key]
        elif ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            out = bytes([key - Qt.Key.Key_A + 1])      # Ctrl+C → \x03 (SIGINT 전달)
        elif ctrl and key in (Qt.Key.Key_BracketLeft, Qt.Key.Key_BracketRight, Qt.Key.Key_Backslash):
            out = bytes([key - 0x40])
        elif e.text():
            out = e.text().encode("utf-8")
        if out is None:
            super().keyPressEvent(e)
            return
        if alt:
            out = b"\x1b" + out
        self._sel_start = self._sel_end = None
        self.input_bytes.emit(out)

    def wheelEvent(self, e) -> None:  # noqa: N802
        d = e.angleDelta().y()
        if d > 0:
            self.screen.prev_page()
        elif d < 0:
            self.screen.next_page()
        self.update()

    # --- 크기 ---
    def resizeEvent(self, _e) -> None:  # noqa: N802
        self._recalc_size()

    def _recalc_size(self) -> None:
        cols = max(20, self.width() // self._cw)
        rows = max(5, self.height() // self._ch)
        if (cols, rows) != (self.cols, self.rows):
            self.cols, self.rows = cols, rows
            self.screen.resize(rows, cols)
            self.resized.emit(cols, rows)
        self.update()

    # --- 메뉴 ---
    def _context_menu(self, pos: QPoint) -> None:
        m = QMenu(self)
        m.addAction("복사  (Ctrl+Shift+C)", self.copy_selection)
        m.addAction("붙여넣기  (Ctrl+Shift+V)", self.paste_clipboard)
        m.addSeparator()
        bigger = QAction("글꼴 크게", self)
        bigger.triggered.connect(lambda: self.set_font_size(self._font_size + 1))
        smaller = QAction("글꼴 작게", self)
        smaller.triggered.connect(lambda: self.set_font_size(self._font_size - 1))
        m.addAction(bigger)
        m.addAction(smaller)
        m.exec(self.mapToGlobal(pos))


# ------------------------------------------------------------------ 페이지
class TerminalPage(QWidget):
    """호스트별 터미널 탭. 헤더에 ⏺ 기록 중 · 브로드캐스트 참여 표시."""

    closed = Signal(object)          # self
    broadcast_input = Signal(bytes)  # 브로드캐스트 허브로

    def __init__(self, host: Host, cred: Credential, approve, log_dir: Path,  # noqa: ANN001
                 record: bool = True) -> None:
        super().__init__()
        self.host = host
        self._recorder: TerminalRecorder | None = None
        if record:
            ts = time.strftime("%Y%m%d_%H%M%S")
            self._recorder = TerminalRecorder(log_dir / f"{host.label}_{ts}.log", host_label=host.label)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.setContentsMargins(8, 4, 8, 4)
        self.status = QLabel("● 연결 중…")
        self.status.setStyleSheet(f"color:{BADGE['running']}")
        head.addWidget(self.status)
        head.addWidget(QLabel(f"{host.username}@{host.address}:{host.port}"))
        head.addStretch(1)
        self.broadcast = QCheckBox("브로드캐스트 수신")
        head.addWidget(self.broadcast)
        rec = QLabel("⏺ 기록 중" if record else "기록 안 함")
        rec.setStyleSheet("color:#F85149" if record else "color:#8B949E")
        head.addWidget(rec)
        lay.addLayout(head)

        self.term = TerminalWidget()
        lay.addWidget(self.term, 1)

        self._thread = QThread()
        self._session = TerminalSession(host, cred, approve, self.term.cols, self.term.rows)
        self._session.moveToThread(self._thread)
        self._thread.started.connect(self._session.run)
        self._session.connected.connect(self._on_connected)
        self._session.data.connect(self._on_data)
        self._session.error.connect(self._on_error)
        self._session.closed.connect(self._on_closed)
        self.term.input_bytes.connect(self._on_input)
        self.term.resized.connect(self._session.resize)
        self._thread.start()

    # --- 세션 이벤트 (UI 스레드) ---
    def _on_connected(self) -> None:
        self.status.setText("● 연결됨")
        self.status.setStyleSheet(f"color:{BADGE['connected']}")
        self.term.setFocus()

    def _on_data(self, b: bytes) -> None:
        self.term.feed(b)
        if self._recorder:
            self._recorder.on_output(b)

    def _on_input(self, b: bytes) -> None:
        self.send(b)
        self.broadcast_input.emit(b)

    def send(self, b: bytes) -> None:
        """이 세션에만 전송(브로드캐스트 허브가 호출)."""
        if self._recorder:
            self._recorder.on_input(b)
        self._session.send(b)

    def _on_error(self, msg: str) -> None:
        self.status.setText(f"✕ {msg}")
        self.status.setStyleSheet(f"color:{BADGE['failed']}")
        self.term.feed(f"\r\n\x1b[31m[InfraGuard] {msg}\x1b[0m\r\n".encode())

    def _on_closed(self, msg: str) -> None:
        self.status.setText(f"○ {msg}")
        self.status.setStyleSheet(f"color:{BADGE['idle']}")

    def shutdown(self) -> None:
        self._session.stop()
        self._thread.quit()
        self._thread.wait(3000)
        if self._recorder:
            self._recorder.close()
        self.closed.emit(self)
