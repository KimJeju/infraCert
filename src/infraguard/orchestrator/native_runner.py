"""네이티브 룰 실행기(B안) — 스크립트 업로드 없이 SSH 명령만으로 점검.

룰 하나의 예외가 다른 룰을 죽이지 않는다. 예외는 ERROR 결과로 표현하되
Status 확정은 result.engine.error_result → decide() 에 맡긴다.
플랫폼 불일치 룰은 SKIPPED(prerequisite) 로 드러낸다 — 조용히 빼지 않는다.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from infraguard.core.models import CheckResult, RawFinding, RemoteEnvironment, SourceInfo
from infraguard.result.engine import error_result
from infraguard.rules import NativeRule, load_all
from infraguard.rules.policy import PolicyError, check_argv
from infraguard.transport.base import Connection, ExecResult

log = logging.getLogger(__name__)

BUNDLE_ID = "native"


class _Guarded:
    """룰에 건네는 연결. 모든 exec 를 (1) 안전 정책으로 막고 (2) 판정 추적용으로 기록한다.

    YAML 룰이든 파이썬 룰이든 명령은 전부 여기를 지난다 — 로더가 걸러도 실행 엔진이 다시 본다.
    """

    def __init__(self, conn: Connection) -> None:
        self._c = conn
        self.commands: list[dict[str, Any]] = []

    def __getattr__(self, name: str) -> Any:            # probe/upload/… 는 그대로 위임
        return getattr(self._c, name)

    def exec(self, argv: list[str], **kw: Any) -> ExecResult:  # noqa: A003
        bad = check_argv(argv)
        if bad:
            raise PolicyError("정책 위반 명령 실행 거부: " + "; ".join(bad))
        r = self._c.exec(argv, **kw)
        self.commands.append({
            "argv": list(argv), "exit_code": r.exit_code,
            "stdout_sha256": hashlib.sha256((r.stdout or "").encode("utf-8", "replace")).hexdigest(),
            "stdout_bytes": len(r.stdout or ""), "duration_ms": r.duration_ms,
            "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
            **({"error": r.error} if r.error else {}), **({"timed_out": True} if r.timed_out else {}),
        })
        return r


def _transport_name(conn: Connection) -> str:
    return type(conn).__name__.removesuffix("Connection").lower() or "unknown"


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

    # PowerShell 수집 명령은 프로세스 기동이 비싸다(룰당 ~1s). 전송이 지원하면 한 스크립트로 미리 받아 둔다.
    prefetch = getattr(conn, "prefetch_powershell", None)
    if prefetch is not None:
        cmds: list[str] = []
        for rid in rule_ids:
            rule = registry.get(rid)
            if rule is None or (env.os and env.os not in rule.platforms):
                continue
            cmds += [c for sh, c in rule.collects if sh == "powershell" and c not in cmds
                     and not check_argv(["powershell", "-Command", c])]   # 위반 명령은 배치에도 안 싣는다
        if cmds:
            try:
                prefetch(cmds)
            except Exception as e:  # noqa: BLE001 - 배치 실패는 개별 실행으로 폴백(성능만 잃는다)
                log.warning("powershell prefetch failed, falling back to per-rule exec: %s", e)

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
        guarded = _Guarded(conn)
        try:
            out = rule.check(guarded, env)   # type: ignore[arg-type]
            findings.append(RawFinding(
                rule_id=rid, name=rule.name, severity_raw=rule.severity,
                verdict_raw=out.verdict_raw, evidence_raw=out.evidence,
                source=SourceInfo(bundle_id=BUNDLE_ID, artifact="ssh-exec", profile="native"),
                provenance={"transport": _transport_name(conn), "impl": "yaml" if rule.collects else "python",
                            "commands": guarded.commands, **out.detail},
            ))
        except Exception as e:  # noqa: BLE001 - 룰 격리
            log.exception("native rule %s failed", rid)
            errors.append(error_result(rid, f"{type(e).__name__}: {e}", bundle_id=BUNDLE_ID,
                                       name=rule.name))
        if progress:
            progress(rid, i, len(rule_ids))
    return findings, errors
