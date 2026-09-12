"""위험도 — 판정(VULN)과 분리된 별도 축: 가이드 중요도 × 자산 중요도.

초기 모델은 4단계 곱셈표다. 정교한 점수(노출도·악용 가능성)는 데이터가 쌓인 뒤에.
ponytail: 3×4 곱 → 구간. 노출도/악용성 축이 필요해지면 여기 한 함수만 바꾼다.
"""

from __future__ import annotations

from infraguard.core.models import ScanResult
from infraguard.core.status import Severity, Status

LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
LABEL_KO = {"CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"}
COLOR = {"CRITICAL": "#F85149", "HIGH": "#F0883E", "MEDIUM": "#D29922", "LOW": "#8B949E"}
CRITICALITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")          # 자산 중요도(Host.criticality)
ENVIRONMENTS = ("", "PROD", "DR", "TEST", "DEV")                # 자산 환경(Host.environment)
DEFAULT_CRITICALITY = "MEDIUM"

_SEV = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, None: 2}
_CRIT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def level(severity: Severity | None, criticality: str | None) -> str:
    score = _SEV.get(severity, 2) * _CRIT.get((criticality or DEFAULT_CRITICALITY).upper(), 2)
    if score >= 9:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def summary(scan: ScanResult) -> dict[str, int]:
    """취약(FAIL) 항목의 위험도 분포. 호스트 자산 중요도는 진단 시점 스냅샷(HostResult.asset)."""
    out = dict.fromkeys(LEVELS, 0)
    for h in scan.hosts:
        crit = h.asset.get("criticality")
        for r in h.results:
            if r.status is Status.FAIL:
                out[level(r.severity, crit)] += 1
    return out
