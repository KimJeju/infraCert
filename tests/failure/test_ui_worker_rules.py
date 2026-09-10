"""UI 스레딩·크리덴셜 정적 규칙(§3.2, §14).

워커 코드는 QWidget 을 만지지 않고(위젯 모듈 미import), Secret/Credential 을
시그널 페이로드에 싣지 않으며, reveal() 을 호출하지 않는다.
정적 스캔이므로 PySide6 설치가 없어도 돈다. 주석/독스트링에 낚이지 않도록 AST 로 검사한다.
"""
import ast
import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "infraguard"
WORKERS = SRC / "ui" / "workers.py"


def _imported_modules(text: str) -> set[str]:
    mods: set[str] = set()
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_worker_does_not_import_widgets():
    """QtWidgets 를 import 하지 않으면 위젯을 만질 수 없다."""
    mods = _imported_modules(WORKERS.read_text(encoding="utf-8"))
    assert not any("QtWidgets" in m for m in mods), f"워커가 위젯 모듈 import: {mods}"


def test_signals_carry_no_secret():
    """Signal(...) 선언에 Secret/Credential 타입이 실리지 않는다."""
    offenders = []
    for line in WORKERS.read_text(encoding="utf-8").splitlines():
        if re.search(r"\bSignal\s*\(", line) and ("Secret" in line or "Credential" in line):
            offenders.append(line.strip())
    assert not offenders, f"시그널에 비밀 타입: {offenders}"


def test_worker_never_reveals():
    """reveal() 은 transport 계층에서만. 워커에는 없다."""
    assert ".reveal()" not in WORKERS.read_text(encoding="utf-8")
