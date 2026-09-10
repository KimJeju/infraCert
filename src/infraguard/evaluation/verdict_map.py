"""판정 어휘 매핑.

기존 스크립트 자산 실사에서 확인된 어휘가 7종 이상 산재한다.
    양호 / 취약 / 수동 / 수동확인 / N/A / N-A / 해당없음
    GOOD / VULN / MANUAL / NA

미등록 어휘를 임의로 PASS 로 떨어뜨리지 않는다. UNKNOWN + 경고로 드러낸다.
"""

from __future__ import annotations

from infraguard.core.status import Status

DEFAULT_VERDICT_MAP: dict[str, Status] = {
    # 양호
    "양호": Status.PASS, "GOOD": Status.PASS, "PASS": Status.PASS, "O": Status.PASS,
    # 취약
    "취약": Status.FAIL, "VULN": Status.FAIL, "FAIL": Status.FAIL, "X": Status.FAIL,
    "위험": Status.FAIL, "미흡": Status.FAIL,
    # 수동확인
    "수동": Status.UNKNOWN, "수동확인": Status.UNKNOWN, "MANUAL": Status.UNKNOWN,
    "확인필요": Status.UNKNOWN, "검토필요": Status.UNKNOWN, "인터뷰": Status.UNKNOWN,
    # 해당없음
    "N/A": Status.SKIPPED, "N-A": Status.SKIPPED, "NA": Status.SKIPPED,
    "해당없음": Status.SKIPPED, "해당사항없음": Status.SKIPPED, "미해당": Status.SKIPPED,
    "SKIP": Status.SKIPPED, "SKIPPED": Status.SKIPPED,
    # 실행오류
    "ERROR": Status.ERROR, "오류": Status.ERROR, "실행오류": Status.ERROR,
}


def normalize_verdict(raw: str | None) -> tuple[Status | None, bool]:
    """원문 판정 어휘를 Status 로. 반환: (status, unmapped)

    unmapped=True 이면 호출측이 UNKNOWN 으로 처리하고 경고를 남긴다.
    """
    if raw is None:
        return None, True
    key = raw.strip().strip("[]()")
    if not key:
        return None, True
    if key in DEFAULT_VERDICT_MAP:
        return DEFAULT_VERDICT_MAP[key], False
    upper = key.upper()
    if upper in DEFAULT_VERDICT_MAP:
        return DEFAULT_VERDICT_MAP[upper], False
    # 공백 제거 후 재시도 ("수동 확인" 등)
    squeezed = "".join(key.split())
    if squeezed in DEFAULT_VERDICT_MAP:
        return DEFAULT_VERDICT_MAP[squeezed], False
    return None, True
