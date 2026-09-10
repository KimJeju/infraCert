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
def ignored() -> set[str]:
    """.gitignore 규칙에 걸려 git 이 무시하는 파일들. (아직 add 안 한 새 파일은 여기 없다)"""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("git 작업트리 아님")
    out = _git("ls-files", "--others", "--ignored", "--exclude-standard", "--", "src", "rulepacks", "tests")
    return {ln for ln in out.splitlines() if "__pycache__" not in ln and not ln.endswith(".pyc")
            and ".egg-info" not in ln}


def test_no_source_package_is_gitignored(ignored):
    hit = sorted(p for p in ignored if p.startswith("src/infraguard/") and p.endswith(".py"))
    assert not hit, f".gitignore 가 소스를 무시한다(규칙 범위 확인): {hit}"


def test_no_rulepack_file_is_gitignored(ignored):
    hit = sorted(p for p in ignored if p.startswith("rulepacks/") and p.endswith((".yaml", ".sh", ".sql")))
    assert not hit, f".gitignore 가 룰팩 파일을 무시한다: {hit}"


def test_no_test_file_is_gitignored(ignored):
    hit = sorted(p for p in ignored if p.startswith("tests/") and p.endswith(".py"))
    assert not hit, f".gitignore 가 테스트를 무시한다: {hit}"
