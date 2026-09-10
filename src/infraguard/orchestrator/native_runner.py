"""네이티브 룰 실행기(B안) — 스크립트 업로드 없이 SSH 명령만으로 점검.

룰 하나의 예외가 다른 룰을 죽이지 않는다. 예외는 ERROR 결과로 표현하되
Status 확정은 result.engine.error_result → decide() 에 맡긴다.
플랫폼 불일치 룰은 SKIPPED(prerequisite) 로 드러낸다 — 조용히 빼지 않는다.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from infraguard.core.models import CheckResult, RawFinding, RemoteEnvironment, SourceInfo
from infraguard.result.engine import error_result
from infraguard.rules import NativeRule, load_all
from infraguard.transport.base import Connection

log = logging.getLogger(__name__)

BUNDLE_ID = "native"


def run_native(
    conn: Connection,
    env: RemoteEnvironment,
    rule_ids: list[str],
    *,
    progress: Callable[[str, int, int], None] | None = None,
    should_cancel: Callable[[], bool] = lambda: False,
) -> tuple[list[RawFinding], list[CheckResult]]:
    """반환: (판정 대상 findings, 실행단계 오류 결과들)."""
    registry = load_all()
    findings: list[RawFinding] = []
    errors: list[CheckResult] = []

    for i, rid in enumerate(rule_ids, start=1):
        if should_cancel():
            errors.append(error_result(rid, "사용자 취소", bundle_id=BUNDLE_ID))
            continue
        rule: NativeRule | None = registry.get(rid)
        if rule is None:
            errors.append(error_result(rid, f"등록되지 않은 네이티브 룰: {rid}", bundle_id=BUNDLE_ID))
            continue
        if env.os and env.os not in rule.platforms:
            errors.append(error_result(
                rid, "", bundle_id=BUNDLE_ID, name=rule.name,
                prerequisite=f"플랫폼 불일치: 룰 {rule.platforms} / 대상 {env.os}",
            ))
            continue
        try:
            out = rule.check(conn, env)
            findings.append(RawFinding(
                rule_id=rid, name=rule.name, severity_raw=rule.severity,
                verdict_raw=out.verdict_raw, evidence_raw=out.evidence,
                source=SourceInfo(bundle_id=BUNDLE_ID, artifact="ssh-exec", profile="native"),
            ))
        except Exception as e:  # noqa: BLE001 - 룰 격리
            log.exception("native rule %s failed", rid)
            errors.append(error_result(rid, f"{type(e).__name__}: {e}", bundle_id=BUNDLE_ID,
                                       name=rule.name))
        if progress:
            progress(rid, i, len(rule_ids))
    return findings, errors
