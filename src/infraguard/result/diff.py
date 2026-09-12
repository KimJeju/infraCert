"""전회 대비 변화 분류 — "몇 개 취약인가" 보다 "조치가 얼마나 됐는가".

기준(baseline)에 있는 호스트만 분류한다. 처음 진단한 호스트의 취약을 '신규' 로 세면 조치율이 왜곡된다.
"""

from __future__ import annotations

from infraguard.core.models import ScanResult
from infraguard.core.status import Status

FIXED = "FIXED"            # 취약 → 양호
REGRESSED = "REGRESSED"    # 양호 → 취약
STILL_VULN = "STILL_VULN"  # 취약 유지
NEW_VULN = "NEW_VULN"      # 전회 취약 아니었음(수동/NA/오류/미점검) → 취약
ORDER = (FIXED, REGRESSED, STILL_VULN, NEW_VULN)
LABEL_KO = {FIXED: "조치됨", REGRESSED: "재발", STILL_VULN: "취약 유지", NEW_VULN: "신규 취약"}
COLOR = {FIXED: "#3FB950", REGRESSED: "#F85149", STILL_VULN: "#D29922", NEW_VULN: "#A371F7"}

Key = tuple[str, str]   # (hostname, rule_id)


def classify(prev: Status | None, cur: Status, *, host_in_base: bool) -> str | None:
    if not host_in_base:
        return None
    if cur is Status.FAIL:
        if prev is Status.FAIL:
            return STILL_VULN
        if prev is Status.PASS:
            return REGRESSED
        return NEW_VULN
    if prev is Status.FAIL and cur is Status.PASS:
        return FIXED
    return None


def diff(scan: ScanResult, base: ScanResult | None) -> dict[Key, tuple[Status | None, str | None]]:
    """(hostname, rule_id) → (전회 결과, 분류). base 없으면 빈 dict."""
    if base is None:
        return {}
    prev = {(h.hostname, r.rule_id): r.status for h in base.hosts for r in h.results}
    base_hosts = {h.hostname for h in base.hosts}
    out: dict[Key, tuple[Status | None, str | None]] = {}
    for h in scan.hosts:
        for r in h.results:
            p = prev.get((h.hostname, r.rule_id))
            out[(h.hostname, r.rule_id)] = (p, classify(p, r.status, host_in_base=h.hostname in base_hosts))
    return out


def summary(d: dict[Key, tuple[Status | None, str | None]]) -> dict[str, int]:
    out = dict.fromkeys(ORDER, 0)
    for _, cls in d.values():
        if cls:
            out[cls] += 1
    return out


def fix_rate(s: dict[str, int]) -> float | None:
    """전회 취약 중 조치된 비율. 전회 취약이 없으면 None."""
    denom = s.get(FIXED, 0) + s.get(STILL_VULN, 0)
    return None if denom == 0 else s.get(FIXED, 0) / denom
