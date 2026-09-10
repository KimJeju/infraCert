"""종료·완전삭제 결정 로직(§11) — 순수 함수로 분리해 테스트 가능하게 한다.

결과를 잃는 사고가 잔류물보다 흔하다. 미반출 경고를 반드시 우선한다.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExitState:
    scanning: bool          # 진행 중 진단이 있는가
    unexported: bool        # 아직 내보내지 않은 결과가 있는가


# 종료 흐름에서 사용자에게 물어야 하는 관문
CONFIRM_SCANNING = "confirm_scanning"    # "진단 진행 중. 중단할까요?"
WARN_UNEXPORTED = "warn_unexported"      # "아직 내보내지 않은 결과가 있습니다"
PROCEED = "proceed"                      # 정리·종료 진행


def exit_gate(state: ExitState) -> str:
    """다음에 띄워야 할 관문 하나를 돌려준다. 진행 중 진단이 최우선."""
    if state.scanning:
        return CONFIRM_SCANNING
    if state.unexported:
        return WARN_UNEXPORTED
    return PROCEED
