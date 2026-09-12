"""예외/보상통제 — "취약이지만 승인된 예외" 를 판정과 섞지 않고 옆에 둔다.

판정(Status)은 그대로 VULN 이다. 예외는 호스트×룰 단위 메타이며 만료일이 있다.
만료된 예외는 자동으로 효력을 잃고(EXPIRED) 리포트 게이트에 걸린다.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field

APPROVED = "APPROVED"
EXPIRED = "EXPIRED"
LABEL_KO = {APPROVED: "예외 승인", EXPIRED: "예외 만료"}


class RiskException(BaseModel):
    host_id: str
    rule_id: str
    reason: str                              # 왜 예외인가(보상통제 설명 포함)
    approver: str = ""
    control: str = ""                        # 보상통제(AD 정책·MFA·PAM 등)
    approved_at: str = Field(default_factory=lambda: date.today().isoformat())
    expires_at: str | None = None            # ISO date. None = 무기한(권장하지 않음)

    def state(self, today: date | None = None) -> str:
        if not self.expires_at:
            return APPROVED
        return EXPIRED if date.fromisoformat(self.expires_at) < (today or date.today()) else APPROVED

    def days_left(self, today: date | None = None) -> int | None:
        if not self.expires_at:
            return None
        return (date.fromisoformat(self.expires_at) - (today or date.today())).days

    def label(self, today: date | None = None) -> str:
        st = self.state(today)
        d = self.days_left(today)
        if st == EXPIRED:
            return f"만료 {-d}일 경과" if d is not None else "만료"
        return "승인 (무기한)" if d is None else f"승인 D-{d}"
