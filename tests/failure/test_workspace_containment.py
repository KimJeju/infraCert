"""고객사 PC 잔류물 — 작업공간 밖에 쓰지 않고, 완전 삭제된다."""
import pathlib, tempfile
from infraguard.workspace.layout import Layout
from infraguard.workspace.manager import Workspace

def test_path_traversal_contained():
    """경로 조각에 traversal 을 넣어도 workspace 밖으로 나가지 못한다.

    검사 기준은 문자열이 아니라 '세그먼트'다.
    구분자를 치환한 결과가 '_.._etc' 처럼 보일 수는 있으나 이는 단일 디렉터리명이며
    상위로 올라가지 않는다.
    """
    lay = Layout(pathlib.Path(tempfile.mkdtemp()) / "ws")
    for bad in ("../../etc", "..\\..\\windows", "..", ".", "C:\\Windows", "a/../../b"):
        evil = lay.host_dir(bad, bad)
        assert lay.contains(evil), f"{bad!r} 가 workspace 밖으로 나갔다"
        segments = evil.relative_to(lay.root).parts
        assert ".." not in segments, f"{bad!r} -> traversal 세그먼트 {segments}"
        assert all(seg not in ("", ".") for seg in segments)

def test_contains_rejects_outside():
    base = pathlib.Path(tempfile.mkdtemp())
    lay = Layout(base / "ws")
    assert not lay.contains(base / "outside.txt")

def test_sanitize_removes_everything():
    ws = Workspace(pathlib.Path(tempfile.mkdtemp()) / "ws")
    lay = ws.create()
    d = lay.host_dir("S1", "H1"); d.mkdir(parents=True)
    (d / "result.csv").write_text("x", encoding="utf-8")
    lay.assets_db.write_text("db", encoding="utf-8")
    (lay.logs / "run.log").write_text("log", encoding="utf-8")
    rep = ws.sanitize()
    assert rep.clean, f"잔류: {rep.leftovers} 오류: {rep.errors}"
    assert not lay.root.exists()

def test_sanitize_on_missing_workspace_is_safe():
    ws = Workspace(pathlib.Path(tempfile.mkdtemp()) / "never-created")
    assert ws.sanitize().clean
