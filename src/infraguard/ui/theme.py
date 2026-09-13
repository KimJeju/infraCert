"""색상 토큰 단일 정의 (§1.1 배지 · §6.1 상태 배경) + 다크 QSS.

배지 색과 결과 상태 배경색을 여기 한 곳에서만 정의한다. GitHub 다크 계열 팔레트.
"""

from __future__ import annotations

from pathlib import Path

from infraguard.core.status import Status

# 화살표·체크 SVG. 서브컨트롤에 QSS 를 주면 Windows 기본 화살표가 사라지므로 직접 그린다(border 삼각형은 스타일에 따라 막대로 깨짐)
_ASSETS = Path(__file__).resolve().parent / "theme"
ARROW_DOWN = (_ASSETS / "arrow_down.svg").as_posix()
ARROW_UP = (_ASSETS / "arrow_up.svg").as_posix()
CHECK = (_ASSETS / "check.svg").as_posix()

# --- 기본 팔레트 (거의 흑색, 저채도. 둥근 모서리 없음, 선은 1px) ---
BG0 = "#07090C"      # 캔버스
BG1 = "#0C0F14"      # 패널·헤더
BG2 = "#12161C"      # 컨트롤
BG3 = "#1E242D"      # 테두리
FG0 = "#D7DDE6"      # 본문
FG1 = "#7D8794"      # 보조
ACCENT = "#3D7BFF"
ACCENT_DIM = "#2455B8"

# --- 호스트 상태 배지 (§1.1) — 연결/실행 상태, 진단 판정 아님 ---
BADGE = {
    "connected": "#2EA043",
    "running": "#D29922",
    "idle": "#8B949E",
    "failed": "#F85149",
    "warn": "#F85149",
}

# --- 진단 결과 상태 배경 (§6.1) : 밝은 칩(표 셀·카드) ---
STATUS_BG = {
    Status.PASS: "#0F2A1A",
    Status.FAIL: "#3A1214",
    Status.UNKNOWN: "#33270A",
    Status.SKIPPED: "#161A20",
    Status.ERROR: "#2A1B3D",
}
# 상태 칩 글자색(다크 칩 위)
STATUS_TEXT = {
    Status.PASS: "#4ADE80",
    Status.FAIL: "#F87171",
    Status.UNKNOWN: "#FBBF24",
    Status.SKIPPED: "#9CA3AF",
    Status.ERROR: "#C084FC",
}
# 상태 = 색 + 아이콘 + 텍스트 (색만으로 구분하지 않는다 — 접근성)
STATUS_ICON = {
    Status.PASS: "✓",
    Status.FAIL: "✗",
    Status.UNKNOWN: "?",
    Status.SKIPPED: "–",
    Status.ERROR: "!",
}


def status_label(st: Status) -> str:
    from infraguard.core.status import DISPLAY_KO
    return f"{STATUS_ICON[st]} {DISPLAY_KO[st]}"


# 다크 배경 위 상태 텍스트/막대 색
STATUS_FG = {
    Status.PASS: "#3FB950",
    Status.FAIL: "#F85149",
    Status.UNKNOWN: "#D29922",
    Status.SKIPPED: "#8B949E",
    Status.ERROR: "#A371F7",
}

DARK_QSS = f"""
* {{ font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; font-size: 12px; }}
QMainWindow, QDialog, QWidget {{ background: {BG0}; color: {FG0}; }}
QMainWindow#root {{ border: 1px solid {BG3}; }}
QToolTip {{ background: {BG1}; color: {FG0}; border: 1px solid {BG3}; padding: 4px; }}

/* ---- 자체 타이틀바 ---- */
QWidget#titlebar {{ background: {BG1}; border-bottom: 1px solid {BG3}; }}
QLabel#title-mark {{ color: {ACCENT}; font-size: 10px; }}
QLabel#title-text {{ color: {FG0}; font-weight: 700; letter-spacing: 2px; font-size: 12px; }}
QLabel#title-sub {{ color: {FG1}; font-size: 11px; }}
QToolButton#title-btn {{ background: transparent; border: none; color: {FG1}; font-size: 12px; }}
QToolButton#title-btn:hover {{ background: {BG2}; color: {FG0}; }}
QToolButton#title-close:hover {{ background: #B42318; color: white; }}

/* ---- 메뉴 ---- */
QMenuBar {{ background: {BG1}; color: {FG1}; border-bottom: 1px solid {BG3}; padding: 0 4px; }}
QMenuBar::item {{ padding: 5px 10px; }}
QMenuBar::item:selected {{ background: {BG2}; color: {FG0}; }}
QMenu {{ background: {BG1}; color: {FG0}; border: 1px solid {BG3}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 12px; }}
QMenu::item:selected {{ background: {ACCENT_DIM}; color: white; }}
QMenu::separator {{ height: 1px; background: {BG3}; margin: 4px 8px; }}

/* ---- 입력 ---- */
/* 높이를 명시하지 않으면 Windows 스타일에서 padding 만큼 글자가 위아래로 잘린다(09-11 형 스크린샷) */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG0}; border: 1px solid {BG3}; padding: 3px 8px; min-height: 24px;
    color: {FG0}; selection-background-color: {ACCENT_DIM};
}}
QPlainTextEdit, QTextEdit {{ padding: 6px 8px; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {{ border: 1px solid {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; subcontrol-origin: padding; subcontrol-position: center right; }}
QComboBox::down-arrow {{ image: url("{ARROW_DOWN}"); width: 10px; height: 6px; margin-right: 6px; }}
QComboBox QAbstractItemView::item {{ min-height: 24px; padding: 3px 8px; }}
QComboBox QAbstractItemView::item:selected {{ background: {ACCENT_DIM}; color: white; }}
QComboBox QAbstractItemView {{ background: {BG1}; border: 1px solid {BG3}; selection-background-color: {ACCENT_DIM}; }}
QSpinBox {{ padding-right: 22px; }}
QSpinBox::up-button, QSpinBox::down-button {{
    width: 18px; border: none; background: {BG2}; subcontrol-origin: border;
}}
QSpinBox::up-button {{ subcontrol-position: top right; }}
QSpinBox::down-button {{ subcontrol-position: bottom right; }}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{ background: {BG3}; }}
QSpinBox::up-arrow {{ image: url("{ARROW_UP}"); width: 8px; height: 5px; }}
QSpinBox::down-arrow {{ image: url("{ARROW_DOWN}"); width: 8px; height: 5px; }}
QCheckBox, QRadioButton {{ spacing: 6px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 15px; height: 15px; border: 1px solid {BG3}; background: {BG0}; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; image: url("{CHECK}"); }}

/* ---- 버튼 ---- */
QPushButton {{
    background: {BG2}; border: 1px solid {BG3};
    padding: 5px 14px; color: {FG0}; min-height: 24px;
}}
QPushButton:hover {{ border-color: #3A4452; background: #171C23; }}
QPushButton:pressed {{ background: {BG1}; }}
QPushButton:disabled {{ color: #4B5563; border-color: {BG2}; }}
QPushButton#primary {{ background: {ACCENT_DIM}; border-color: {ACCENT}; color: white; font-weight: 600; }}
QPushButton#primary:hover {{ background: {ACCENT}; }}
QPushButton#primary:disabled {{ background: #14213A; border-color: #1B2B4D; color: #4B5563; }}
QPushButton#danger {{ background: transparent; border-color: #7F1D1D; color: #EF4444; }}
QPushButton#danger:hover {{ background: #B42318; border-color: #B42318; color: white; }}

/* ---- 뷰 ---- */
QTreeView, QTableView, QTableWidget, QTreeWidget, QListWidget {{
    background: {BG0}; border: 1px solid {BG3};
    alternate-background-color: #10151C; gridline-color: {BG3};
    selection-background-color: {ACCENT_DIM}; selection-color: white; outline: 0;
}}
/* 셀에 직접 브러시(판정 색)를 준 항목이 선택되면 Windows 스타일에서 검게 그려진다 → 선택 색을 명시로 강제 */
QTableView::item:selected, QTableWidget::item:selected {{ background: {ACCENT_DIM}; color: white; }}
QTreeView::item, QListWidget::item {{ padding: 3px 4px; }}
QTreeView::item:hover, QListWidget::item:hover {{ background: {BG1}; }}
QTreeView::branch {{ background: transparent; }}
QHeaderView::section {{
    background: {BG1}; color: {FG1}; border: none; border-right: 1px solid {BG3};
    border-bottom: 1px solid {BG3}; padding: 5px 8px; font-weight: 600; font-size: 11px; letter-spacing: 1px;
}}
QTableWidget QTableCornerButton::section {{ background: {BG1}; border: none; }}

/* ---- 탭 ---- */
QTabWidget::pane {{ border: 1px solid {BG3}; top: -1px; background: {BG0}; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent; color: {FG1}; padding: 7px 16px; margin-right: 0;
    border: none; border-bottom: 2px solid transparent; letter-spacing: 1px;
}}
QTabBar::tab:hover {{ color: {FG0}; }}
QTabBar::tab:selected {{ color: {FG0}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::close-button {{ subcontrol-position: right; }}

/* ---- 그룹/구분 ---- */
QGroupBox {{ border: 1px solid {BG3}; margin-top: 10px; padding: 16px 12px 10px 12px; }}
QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; left: 12px; padding: 0 6px;
                    color: {FG1}; font-weight: 600; background: {BG0}; }}
QSplitter::handle {{ background: {BG3}; width: 1px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BG3}; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: #6E7681; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; }}
QScrollBar::handle:horizontal {{ background: {BG3}; min-width: 24px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ---- 상태/진행 ---- */
QStatusBar {{ background: {BG1}; color: {FG1}; border-top: 1px solid {BG3}; }}
QStatusBar::item {{ border: none; }}
QProgressBar {{ border: 1px solid {BG3}; background: {BG1}; text-align: center; color: {FG0}; height: 14px; }}
QProgressBar::chunk {{ background: {ACCENT_DIM}; }}

/* ---- 라벨 역할 ---- */
QLabel#h1 {{ font-size: 15px; font-weight: 700; color: {FG0}; letter-spacing: 1px; }}
QLabel#h2 {{ font-size: 13px; font-weight: 600; color: {FG0}; }}
QLabel#muted {{ color: {FG1}; }}
QLabel#sidebar-title {{ color: {FG1}; font-weight: 700; font-size: 12px; letter-spacing: 1px; }}
QWidget#sidebar {{ background: {BG1}; border-right: 1px solid {BG3}; }}
/* ---- Nav Rail ---- */
QWidget#nav {{ background: {BG1}; border-right: 1px solid {BG3}; }}
QLabel#nav-group {{ color: {FG1}; font-size: 10px; letter-spacing: 2px; padding: 4px 8px 2px 8px; }}
QFrame#nav-sep {{ color: {BG3}; background: {BG3}; max-height: 1px; border: none; }}
QPushButton#nav-btn {{ text-align: left; padding: 7px 12px; border: none; background: transparent; color: {FG1};
                       border-left: 2px solid transparent; min-height: 20px; }}
QPushButton#nav-btn:hover {{ background: {BG2}; color: {FG0}; }}
QPushButton#nav-btn:checked {{ background: {BG2}; color: {FG0}; border-left: 2px solid {ACCENT}; font-weight: 600; }}
/* ---- Command Palette ---- */
QDialog#palette {{ background: {BG1}; border: 1px solid {ACCENT_DIM}; }}
QDialog#palette QLineEdit {{ font-size: 14px; padding: 8px 10px; min-height: 30px; }}
QDialog#palette QListWidget::item {{ padding: 6px 8px; }}
QLabel#kpi-n {{ font-size: 26px; font-weight: 700; color: {FG0}; }}
QLabel#kpi-l {{ color: {FG1}; font-size: 11px; letter-spacing: 1px; }}
QLabel#empty-title {{ font-size: 16px; font-weight: 600; color: {FG0}; }}
QWidget#sidebar QLineEdit {{ background: {BG0}; }}
QWidget#card {{ background: {BG1}; border: 1px solid {BG3}; }}
"""
