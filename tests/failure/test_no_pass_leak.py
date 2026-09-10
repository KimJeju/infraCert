"""오류 상황이 PASS 로 새지 않는지 — 제품의 절대 원칙."""
import pytest
from infraguard.core.decision import DecisionInput, decide
from infraguard.core.status import Status

# 모든 케이스에 evaluated=PASS 를 억지로 넣는다. 그래도 PASS 가 나오면 안 된다.
FAILURE_SIGNALS = [
    ("prereq 미충족", dict(prerequisite_failed=True, prerequisite_reason="psql 없음"), Status.SKIPPED),
    ("timeout",       dict(timed_out=True),                                            Status.ERROR),
    ("프로세스 오류",   dict(process_error="connection reset"),                          Status.ERROR),
    ("exit code 위반", dict(exit_code=1, exit_code_violation=True),                     Status.ERROR),
    ("산출물 없음",     dict(artifact_missing=True),                                     Status.ERROR),
    ("파싱 실패",       dict(parse_error="invalid csv"),                                 Status.ERROR),
    ("결과 누락",       dict(reported=False),                                            Status.UNKNOWN),
    ("미등록 어휘",     dict(verdict_unmapped=True, raw_verdict="보류"),                  Status.UNKNOWN),
    ("수동확인 룰",     dict(manual=True),                                               Status.UNKNOWN),
]

@pytest.mark.parametrize("label,signal,expected", FAILURE_SIGNALS,
                         ids=[c[0] for c in FAILURE_SIGNALS])
def test_failure_never_becomes_pass(label, signal, expected):
    d = decide(DecisionInput(evaluated=Status.PASS, **signal))
    assert d.status is not Status.PASS, f"{label}: 오류가 PASS 로 샜다"
    assert d.status is expected
    assert d.reason, "판정 사유가 비어있다"

def test_only_clean_path_yields_pass():
    d = decide(DecisionInput(raw_verdict="양호", evaluated=Status.PASS))
    assert d.status is Status.PASS

def test_decide_is_the_only_pass_source():
    """decision.py 외의 모듈이 Status.PASS 를 직접 반환하지 않는지."""
    import pathlib, re
    src = pathlib.Path(__file__).resolve().parents[2] / "src" / "infraguard"
    offenders = []
    for f in src.rglob("*.py"):
        if f.name in ("decision.py", "status.py", "verdict_map.py"):
            continue
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"return\s+Status\.PASS", line):
                offenders.append(f"{f.relative_to(src)}:{i}")
    assert not offenders, f"decide() 외부에서 PASS 반환: {offenders}"
