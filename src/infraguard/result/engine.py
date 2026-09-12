"""결과 엔진 — RawFinding 을 CheckResult 로 정규화한다.

책임:
    1. 판정 어휘 -> Status 매핑 (미등록 어휘는 UNKNOWN + 경고)
    2. 판정 확정은 core.decision.decide() 에만 위임
    3. evidence 마스킹 강제
    4. provides 대조 — Bundle 이 담당한다고 선언했는데 산출물에 없는 항목을 드러낸다
"""

from __future__ import annotations

from infraguard.core.decision import DecisionInput, decide
from infraguard.core.models import CheckResult, ExecutionInfo, RawFinding, SourceInfo
from infraguard.core.status import Status, parse_severity
from infraguard.evaluation.verdict_map import normalize_verdict
from infraguard.result.masking import mask

EVIDENCE_INLINE_LIMIT = 8000


def to_check_result(
    f: RawFinding,
    *,
    execution: ExecutionInfo | None = None,
    manual_rules: set[str] | None = None,
) -> CheckResult:
    status_raw, unmapped = normalize_verdict(f.verdict_raw)

    d = decide(
        DecisionInput(
            reported=True,
            raw_verdict=f.verdict_raw,
            verdict_unmapped=unmapped,
            manual=bool(manual_rules and f.rule_id in manual_rules),
            evaluated=status_raw,
        )
    )

    warnings: list[str] = []
    if unmapped:
        warnings.append(f"미등록 판정 어휘: {f.verdict_raw!r}")

    evidence = mask(f.evidence_raw)
    evidence_ref = None
    if evidence and len(evidence) > EVIDENCE_INLINE_LIMIT:
        evidence_ref = f.source.artifact
        evidence = evidence[:EVIDENCE_INLINE_LIMIT] + " …(생략)"
        warnings.append("근거가 길어 일부만 표시. 원본은 회수 산출물 참조")

    return CheckResult(
        rule_id=f.rule_id,
        name=f.name or f.rule_id,
        status=d.status,
        reason=d.reason,
        severity=parse_severity(f.severity_raw),
        evidence=evidence,
        evidence_ref=evidence_ref,
        source=f.source,
        execution=execution or ExecutionInfo(),
        warnings=warnings,
        provenance=f.provenance,
    )


def missing_result(rule_id: str, *, bundle_id: str | None = None,
                   name: str | None = None) -> CheckResult:
    """Bundle 이 provides 했으나 산출물에 없는 항목. 조용히 사라지지 않게 한다."""
    d = decide(DecisionInput(reported=False))
    return CheckResult(
        rule_id=rule_id,
        name=name or rule_id,
        status=d.status,
        reason=d.reason,
        source=SourceInfo(bundle_id=bundle_id),
        warnings=["산출물에 해당 항목이 없습니다"],
    )


def error_result(rule_id: str, reason: str, *, bundle_id: str | None = None,
                 name: str | None = None, execution: ExecutionInfo | None = None,
                 timed_out: bool = False, prerequisite: str = "") -> CheckResult:
    """실행 단계 실패를 항목 결과로 표현한다. 판정은 decide() 가 정한다."""
    d = decide(
        DecisionInput(
            prerequisite_failed=bool(prerequisite),
            prerequisite_reason=prerequisite,
            timed_out=timed_out,
            process_error="" if (timed_out or prerequisite) else reason,
        )
    )
    return CheckResult(
        rule_id=rule_id, name=name or rule_id, status=d.status, reason=d.reason,
        source=SourceInfo(bundle_id=bundle_id), execution=execution or ExecutionInfo(),
    )


def normalize(
    findings: list[RawFinding],
    *,
    provides: list[str] | None = None,
    bundle_id: str | None = None,
    execution: ExecutionInfo | None = None,
    manual_rules: set[str] | None = None,
) -> tuple[list[CheckResult], list[RawFinding]]:
    """반환: (정규화된 결과, 룰팩에 없는 고아 findings)

    provides 가 주어지면 누락 항목을 UNKNOWN 으로 채운다.
    """
    results: list[CheckResult] = []
    seen: set[str] = set()

    for f in findings:
        results.append(to_check_result(f, execution=execution, manual_rules=manual_rules))
        seen.add(f.rule_id)

    if provides:
        for rid in provides:
            if rid not in seen:
                results.append(missing_result(rid, bundle_id=bundle_id))

    orphans: list[RawFinding] = []
    if provides:
        known = set(provides)
        orphans = [f for f in findings if f.rule_id not in known]

    results.sort(key=lambda r: _sort_key(r.rule_id))
    return results, orphans


def _sort_key(rule_id: str) -> tuple[str, int, str]:
    """U-01, U-2, W-10 을 자연 정렬한다."""
    if "-" in rule_id:
        prefix, _, rest = rule_id.partition("-")
        num = "".join(c for c in rest if c.isdigit())
        return (prefix, int(num) if num else 0, rest)
    return (rule_id, 0, "")


def provenance_text(r: CheckResult) -> str:
    """판정 추적을 사람이 읽는 한 덩어리로. 판정 → 명령(종료코드·출력해시) → 추출값 → 매치 절."""
    p = r.provenance
    if not p:
        return ""
    lines = [f"transport={p.get('transport', '-')} impl={p.get('impl', '-')}"]
    for c in p.get("commands") or []:
        argv = c.get("argv") or []
        cmd = argv[-1] if argv else ""
        tail = f" rc={c.get('exit_code')} sha={str(c.get('stdout_sha256', ''))[:12]} {c.get('duration_ms', 0)}ms"
        lines.append(f"$ {cmd}{tail}" + (f" ERROR={c['error']}" if c.get("error") else ""))
    if p.get("extracted"):
        lines.append("추출: " + ", ".join(f"{k}={v!r}" for k, v in p["extracted"].items()))
    if p.get("matched"):
        lines.append("판정식: " + str(p["matched"]))
    return "\n".join(lines)


def summarize(results: list[CheckResult]) -> dict[Status, int]:
    out: dict[Status, int] = {s: 0 for s in Status}
    for r in results:
        out[r.status] += 1
    return out
