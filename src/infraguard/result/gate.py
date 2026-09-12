"""리포트 품질 게이트 — 보고서를 만들기 전에 사고를 막는 자동 검사.

판정하지 않는다. 사실만 나열하고, 통과 못 하면 사용자가 '그래도 생성' 을 고른다(강제 차단 아님).
"""

from __future__ import annotations

from dataclasses import dataclass

from infraguard.core.models import ScanResult
from infraguard.core.status import Status


@dataclass(slots=True)
class GateItem:
    ok: bool
    label: str
    detail: str = ""

    def line(self) -> str:
        return f"{'✓' if self.ok else '✗'} {self.label}" + (f" — {self.detail}" if self.detail else "")


def run(scan: ScanResult, *, pack_sha256: str | None = None, remediation: dict[str, str] | None = None,
        db_ok: bool | None = None, exceptions: dict | None = None,
        rule_shas: dict[str, str] | None = None) -> list[GateItem]:
    rem = remediation or {}
    items: list[GateItem] = []

    bad_hosts = [h.hostname for h in scan.hosts if h.error or not h.results]
    items.append(GateItem(not bad_hosts, "모든 호스트 진단 완료",
                          f"오류/빈 결과 {len(bad_hosts)}대: {', '.join(bad_hosts[:5])}" if bad_hosts else
                          f"{len(scan.hosts)}대"))

    errors = sum(1 for h in scan.hosts for r in h.results if r.status is Status.ERROR)
    items.append(GateItem(errors == 0, "실행오류(ERROR) 0", f"{errors}건 — 재진단 권장" if errors else ""))

    manual_open = sum(1 for h in scan.hosts for r in h.results
                      if r.status is Status.UNKNOWN and r.verdict_source != "analyst")
    manual_done = sum(1 for h in scan.hosts for r in h.results if r.verdict_source == "analyst")
    items.append(GateItem(manual_open == 0, "수동확인 처리",
                          f"미판정 {manual_open}건" if manual_open else f"분석자 판정 {manual_done}건"))

    no_ev = [(h.hostname, r.rule_id) for h in scan.hosts for r in h.results
             if r.status is Status.FAIL and not (r.evidence or "").strip()]
    items.append(GateItem(not no_ev, "취약 항목 근거 존재",
                          f"근거 없는 취약 {len(no_ev)}건: " + ", ".join(f"{h}/{r}" for h, r in no_ev[:5]) if no_ev else ""))

    fail_ids = sorted({r.rule_id for h in scan.hosts for r in h.results if r.status is Status.FAIL})
    no_rem = [rid for rid in fail_ids if not rem.get(rid)]
    items.append(GateItem(not no_rem, "취약 항목 조치방법 존재",
                          f"조치방법 없는 룰 {len(no_rem)}: {', '.join(no_rem[:8])}" if no_rem else f"취약 룰 {len(fail_ids)}종"))

    if pack_sha256 is None:
        items.append(GateItem(True, "룰팩 SHA 확인", "비교 대상 룰팩 없음(생략)"))
    elif not scan.rule_pack_sha256:
        items.append(GateItem(False, "룰팩 SHA 확인", "진단 결과에 룰팩 SHA 기록 없음(구버전 결과)"))
    else:
        same = scan.rule_pack_sha256 == pack_sha256
        items.append(GateItem(same, "룰팩 SHA 확인",
                              f"{scan.rule_pack_sha256[:12]}" if same else
                              f"진단 당시 {scan.rule_pack_sha256[:12]} ≠ 현재 {pack_sha256[:12]} — 룰팩이 바뀜"))

    if db_ok is not None:
        items.append(GateItem(db_ok, "결과 DB 무결성", "" if db_ok else "SQLite quick_check 실패"))

    if rule_shas:
        stale = sorted({r.rule_id for h in scan.hosts for r in h.results
                        if (p := r.provenance) and p.get("rule_sha256") and rule_shas.get(r.rule_id)
                        and p["rule_sha256"] != rule_shas[r.rule_id]})
        items.append(GateItem(not stale, "룰 변경 후 재평가 필요 없음",
                              f"진단 이후 룰이 바뀐 항목 {len(stale)}: {', '.join(stale[:8])} — 재진단 권장" if stale else ""))

    if exceptions is not None:
        applied = [(h.hostname, r.rule_id, exceptions[(h.host_id, r.rule_id)])
                   for h in scan.hosts for r in h.results
                   if r.status is Status.FAIL and (h.host_id, r.rule_id) in exceptions]
        expired = [(hn, rid) for hn, rid, e in applied if e.state() == "EXPIRED"]
        items.append(GateItem(not expired, "만료된 예외 없음",
                              f"만료 {len(expired)}건: " + ", ".join(f"{h}/{r}" for h, r in expired[:5]) if expired
                              else f"예외 적용 {len(applied)}건"))
    return items


def passed(items: list[GateItem]) -> bool:
    return all(i.ok for i in items)


def stale_rule_ids(scan: ScanResult, rule_shas: dict[str, str]) -> set[str]:
    """진단 당시 룰 SHA ≠ 현재 룰 SHA 인 룰 id (Wazuh 식 '정책 변경 → 결과 무효')."""
    return {r.rule_id for h in scan.hosts for r in h.results
            if (p := r.provenance) and p.get("rule_sha256") and rule_shas.get(r.rule_id)
            and p["rule_sha256"] != rule_shas[r.rule_id]}
