"""진단 상태 정의.

절대 원칙: 실행 실패를 진단 실패로 위장하지 않는다.
    SKIPPED -> PASS 금지
    ERROR   -> FAIL 금지
    UNKNOWN -> PASS 금지

내부 로직은 이 Enum만 비교한다. 한글 표시 문자열을 조건문에 쓰지 않는다.
"""

from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    PASS = "PASS"        # 기준 만족
    FAIL = "FAIL"        # 기준 미충족
    UNKNOWN = "UNKNOWN"  # 자동 판정 불가 (수동확인 대상)
    SKIPPED = "SKIPPED"  # 실행 전제조건 미충족
    ERROR = "ERROR"      # 실행 과정에서 오류 발생

    @property
    def is_diagnostic(self) -> bool:
        """진단 판정인가(True) 실행 상태인가(False)."""
        return self in (Status.PASS, Status.FAIL)


# 화면·리포트 표시용. 렌더링 계층에서만 사용한다.
DISPLAY_KO: dict[Status, str] = {
    Status.PASS: "양호",
    Status.FAIL: "취약",
    Status.UNKNOWN: "수동확인",
    Status.SKIPPED: "해당없음",
    Status.ERROR: "실행오류",
}

# 집계 표시 순서
ORDER: tuple[Status, ...] = (
    Status.PASS,
    Status.FAIL,
    Status.UNKNOWN,
    Status.SKIPPED,
    Status.ERROR,
)


class Severity(str, Enum):
    HIGH = "상"
    MEDIUM = "중"
    LOW = "하"


SEVERITY_ALIASES: dict[str, Severity] = {
    "상": Severity.HIGH, "high": Severity.HIGH, "HIGH": Severity.HIGH, "H": Severity.HIGH,
    "중": Severity.MEDIUM, "medium": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "M": Severity.MEDIUM,
    "하": Severity.LOW, "low": Severity.LOW, "LOW": Severity.LOW, "L": Severity.LOW,
}


def parse_severity(raw: str | None) -> Severity | None:
    if raw is None:
        return None
    return SEVERITY_ALIASES.get(raw.strip())
