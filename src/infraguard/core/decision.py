"""판정 우선순위 — 단일 구현 지점.

Status 를 만드는 경로는 이 모듈의 decide() 하나뿐이다.
다른 모듈이 Status.PASS 를 직접 반환하지 않는다. (tests/failure 에서 강제)

우선순위:
    1. Prerequisite 미충족                 -> SKIPPED
    2. Timeout / crash / 실행 불가          -> ERROR
    3. exit code 정책 위반                  -> ERROR
    4. 산출물 부재 / 파싱 실패                -> ERROR
    5. Bundle 이 provides 했으나 결과 누락     -> UNKNOWN
    6. 판정 필드 부재 / 미등록 어휘            -> UNKNOWN
    7. Rule 이 manual 선언                  -> UNKNOWN
    8. 평가                                -> PASS / FAIL
"""

from __future__ import annotations

from dataclasses import dataclass, field

from infraguard.core.status import Status


@dataclass(frozen=True, slots=True)
class DecisionInput:
    # --- 실행 단계 신호 ---
    prerequisite_failed: bool = False
    prerequisite_reason: str = ""

    timed_out: bool = False
    process_error: str = ""          # 비어있지 않으면 ERROR
    exit_code: int | None = None
    exit_code_violation: bool = False

    artifact_missing: bool = False
    parse_error: str = ""            # 비어있지 않으면 ERROR

    # --- 판정 단계 신호 ---
    reported: bool = True            # Bundle 산출물에 이 rule 이 등장했는가
    raw_verdict: str | None = None   # 원문 판정 어휘 (예: "양호")
    verdict_unmapped: bool = False   # 매핑 테이블에 없는 어휘였는가
    manual: bool = False             # Rule 이 수동확인 선언

    evaluated: Status | None = None  # 매핑/평가 결과
    evaluated_reason: str = ""

    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Decision:
    status: Status
    reason: str


def decide(d: DecisionInput) -> Decision:
    """실행 신호와 판정 신호로부터 최종 Status 를 확정한다."""
    if d.prerequisite_failed:
        return Decision(Status.SKIPPED, d.prerequisite_reason or "prerequisite not met")

    if d.timed_out:
        return Decision(Status.ERROR, "timeout")

    if d.process_error:
        return Decision(Status.ERROR, d.process_error)

    if d.exit_code_violation:
        return Decision(Status.ERROR, f"unexpected exit code: {d.exit_code}")

    if d.artifact_missing:
        return Decision(Status.ERROR, "artifact not found")

    if d.parse_error:
        return Decision(Status.ERROR, d.parse_error)

    if not d.reported:
        # Bundle 이 이 rule 을 담당한다고 선언했는데 산출물에 없다.
        # 조용히 사라지게 두지 않는다.
        return Decision(Status.UNKNOWN, "declared by bundle but not reported")

    if d.verdict_unmapped:
        return Decision(Status.UNKNOWN, f"unmapped verdict: {d.raw_verdict!r}")

    if d.manual:
        return Decision(Status.UNKNOWN, "manual review required")

    if d.evaluated is None:
        return Decision(Status.UNKNOWN, "no verdict produced")

    if not d.evaluated.is_diagnostic:
        # 매핑 결과가 SKIPPED(해당없음) 등인 경우 그대로 통과시킨다.
        return Decision(d.evaluated, d.evaluated_reason or f"mapped from {d.raw_verdict!r}")

    return Decision(d.evaluated, d.evaluated_reason or f"mapped from {d.raw_verdict!r}")
