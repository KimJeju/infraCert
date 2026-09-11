"""색상 토큰 단일 정의 (§1.1 배지 · §6.1 상태 배경) + 다크 QSS.

배지 색과 결과 상태 배경색을 여기 한 곳에서만 정의한다. GitHub 다크 계열 팔레트.
"""

from __future__ import annotations

from infraguard.core.status import Status

# --- 기본 팔레트 ---
BG0 = "#0D1117"      # 캔버스
BG1 = "#161B22"      # 패널
BG2 = "#21262D"      # 컨트롤
BG3 = "#30363D"      # 테두리
FG0 = "#E6EDF3"      # 본문
FG1 = "#8B949E"      # 보조
ACCENT = "#2F81F7"
ACCENT_DIM = "#1F6FEB"

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
    Status.PASS: "#E2EFDA",
    Status.FAIL: "#FCE4E4",
    Status.UNKNOWN: "#FFF2CC",
    Status.SKIPPED: "#F2F2F2",
    Status.ERROR: "#E4DFEC",
}
# 다크 배경 위 상태 텍스트/막대 색
STATUS_FG = {
    Status.PASS: "#3FB950",
    Status.FAIL: "#F85149",
    Status.UNKNOWN: "#D29922",
    Status.SKIPPED: "#8B949E",
    Status.ERROR: "#A371F7",
}

DARK_QSS = f"""
* {{ font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; font-size: 13px; }}
QMainWindow, QDialog, QWidget {{ background: {BG0}; color: {FG0}; }}
QToolTip {{ background: {BG1}; color: {FG0}; border: 1px solid {BG3}; padding: 4px; }}

/* ---- 메뉴 ---- */
QMenuBar {{ background: {BG1}; color: {FG0}; border-bottom: 1px solid {BG3}; padding: 2px 4px; }}
QMenuBar::item {{ padding: 4px 10px; }}
QMenuBar::item:selected {{ background: {BG2}; }}
QMenu {{ background: {BG1}; color: {FG0}; border: 1px solid {BG3}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 12px; }}
QMenu::item:selected {{ background: {ACCENT_DIM}; color: white; }}
QMenu::separator {{ height: 1px; background: {BG3}; margin: 4px 8px; }}

/* ---- 입력 ---- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG0}; border: 1px solid {BG3}; padding: 5px 8px;
    color: {FG0}; selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {{ border: 1px solid {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {BG1}; border: 1px solid {BG3}; selection-background-color: {ACCENT_DIM}; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; border: none; background: {BG2}; }}
QCheckBox, QRadioButton {{ spacing: 6px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 15px; height: 15px; border: 1px solid {BG3}; background: {BG0}; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

/* ---- 버튼 ---- */
QPushButton {{
    background: {BG2}; border: 1px solid {BG3}; 
    padding: 6px 14px; color: {FG0}; font-weight: 600;
}}
QPushButton:hover {{ background: {BG3}; border-color: #8B949E; }}
QPushButton:pressed {{ background: {BG1}; }}
QPushButton:disabled {{ color: #6E7681; border-color: {BG2}; }}
QPushButton#primary {{ background: #238636; border-color: #2EA043; color: white; }}
QPushButton#primary:hover {{ background: #2EA043; }}
QPushButton#primary:disabled {{ background: #1a3d24; color: #6E7681; }}
QPushButton#danger {{ background: transparent; border-color: #DA3633; color: #F85149; }}
QPushButton#danger:hover {{ background: #DA3633; color: white; }}

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
    border-bottom: 1px solid {BG3}; padding: 6px 8px; font-weight: 600;
}}
QTableWidget QTableCornerButton::section {{ background: {BG1}; border: none; }}

/* ---- 탭 ---- */
QTabWidget::pane {{ border: 1px solid {BG3}; top: -1px; background: {BG0}; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent; color: {FG1}; padding: 8px 16px; margin-right: 2px;
    border: 1px solid transparent; border-bottom: none; 
}}
QTabBar::tab:hover {{ color: {FG0}; background: {BG1}; }}
QTabBar::tab:selected {{ background: {BG0}; color: {FG0}; border-color: {BG3}; border-top: 2px solid {ACCENT}; }}
QTabBar::close-button {{ subcontrol-position: right; }}

/* ---- 그룹/구분 ---- */
QGroupBox {{ border: 1px solid {BG3}; margin-top: 12px; padding: 12px 8px 6px 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {FG1}; font-weight: 600; }}
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
QProgressBar::chunk {{ background: #238636; }}

/* ---- 라벨 역할 ---- */
QLabel#h1 {{ font-size: 18px; font-weight: 700; color: {FG0}; }}
QLabel#h2 {{ font-size: 14px; font-weight: 600; color: {FG0}; }}
QLabel#muted {{ color: {FG1}; }}
QLabel#sidebar-title {{ color: {FG1}; font-weight: 700; font-size: 12px; letter-spacing: 1px; }}
QWidget#sidebar {{ background: {BG1}; border-right: 1px solid {BG3}; }}
QWidget#sidebar QLineEdit {{ background: {BG0}; }}
QWidget#card {{ background: {BG1}; border: 1px solid {BG3}; }}
"""
