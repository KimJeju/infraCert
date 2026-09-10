"""저장소 위생 — 소스가 조용히 git 에서 빠지지 않는다.

2026-09-10: .gitignore 의 'workspace/' 가 src/infraguard/workspace/ 까지 매칭해 패키지가
한 번도 커밋되지 않았고, 클론한 쪽에서 import 부터 실패했다. 이 테스트는 그 재발을 막는다.
git 이 없거나 작업트리가 아니면 건너뛴다(배포본에서는 의미 없음).
"""
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "infraguard"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout


@pytest.fixture(scope="module")
def tracked() -> set[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("git 작업트리 아님")
    return set(_git("ls-files", "--", "src", "rulepacks", "tests").splitlines())


def test_every_source_package_is_tracked(tracked):
    missing = []
    for init in SRC.rglob("__init__.py"):
        rel = init.relative_to(ROOT).as_posix()
        if rel not in tracked:
            missing.append(rel)
    assert not missing, f"git 에 없는 소스 패키지(ignore 규칙 확인): {missing}"


def test_every_source_module_is_tracked_or_ignored_on_purpose(tracked):
    """*.py 소스 파일 중 추적되지 않는 것은 없어야 한다(캐시 제외)."""
    untracked = []
    for py in SRC.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        rel = py.relative_to(ROOT).as_posix()
        if rel not in tracked:
            untracked.append(rel)
    assert not untracked, f"미추적 소스: {untracked}"


def test_rulepack_rules_and_manifest_tracked(tracked):
    pack = ROOT / "rulepacks" / "kisa-2026"
    need = [pack / "manifest.yaml", *sorted((pack / "rules").glob("*.yaml"))]
    missing = [p.relative_to(ROOT).as_posix() for p in need
               if p.relative_to(ROOT).as_posix() not in tracked]
    assert not missing, f"룰팩 파일 미추적: {missing}"
