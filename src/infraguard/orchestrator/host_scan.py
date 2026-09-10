"""호스트 1대 진단 파이프라인 — 엔진 글루.

HostJob(번들 N개 + 네이티브 룰) 을 받아 HostResult 하나를 만든다.
  번들:   remote_runner(업로드·실행·회수·정리) → tar 안전해제 → 파서 dispatch → normalize(provides 대조)
  네이티브: native_runner(SSH 원시명령) → normalize

절대 예외를 밖으로 던지지 않는다. 한 호스트의 실패가 다른 호스트로 전파되면 안 된다.
실행 실패는 HostResult.error 로, 판정은 core.decision.decide() 로만 표현된다.
tar 해제는 path traversal 을 차단한다(회수 압축파일은 대상 서버가 만든 것이라 신뢰 못 함).
"""

from __future__ import annotations

import logging
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from infraguard.core.models import CheckResult, ExecutionInfo, HostResult, RemoteEnvironment
from infraguard.orchestrator.native_runner import run_native
from infraguard.orchestrator.remote_runner import RemoteRunner, RunSpec
from infraguard.parsing.dispatch import parse_artifact
from infraguard.parsing.legacy_csv import Profile
from infraguard.result.engine import _sort_key, normalize
from infraguard.transport.base import Connection

log = logging.getLogger(__name__)

Progress = Callable[[str], None]

# §5.1 단계 문자열
STAGE_CONNECT = "연결 중"
STAGE_PROBE = "환경 점검"
STAGE_RUN = "실행 중"
STAGE_COLLECT = "산출물 회수"
STAGE_PARSE = "파싱"
STAGE_NATIVE = "네이티브 점검"
STAGE_DONE = "완료"
STAGE_CLEANUP_FAILED = "정리 미완료"


@dataclass(slots=True)
class HostJob:
    """한 호스트에서 수행할 작업. 프로파일에서 만들어진다."""

    bundles: list[tuple[RunSpec, list[str]]] = field(default_factory=list)  # (spec, provides)
    native: list[str] = field(default_factory=list)                          # native rule ids
    manual_rules: set[str] = field(default_factory=set)
    exclude: set[str] = field(default_factory=set)


def _noop(_stage: str) -> None: ...


def safe_extract(archive: Path, dest: Path) -> list[Path]:
    """tar.gz 를 dest 안으로만 해제한다.

    멤버를 하나씩 처리한다. 경로 이탈·심볼릭링크·특수파일은 건너뛴다.
    나쁜 멤버 하나 때문에 나머지 산출물 회수가 중단되면 안 된다(정상 파일만 뽑는다).
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf.getmembers():
            if not (m.isfile() or m.isdir()):
                log.warning("건너뜀(특수 멤버): %s", m.name)
                continue
            target = (dest / m.name).resolve()
            if target != dest and dest not in target.parents:
                log.warning("거부된 아카이브 멤버(경로 이탈): %s", m.name)
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            src = tf.extractfile(m)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as fh:
                fh.write(src.read())
            extracted.append(target)
    return extracted


def _run_bundle(
    conn: Connection, spec: RunSpec, provides: list[str], local_dir: Path, *,
    profiles: list[Profile] | None, manual_rules: set[str], started: datetime,
    progress: Progress, host: HostResult,
) -> list[CheckResult]:
    """번들 하나 실행·파싱. 실행 실패는 host.error 에 누적하고 빈 결과(또는 provides→UNKNOWN)를 돌려준다."""
    progress(f"{STAGE_RUN} ({spec.bundle_id})")
    res = RemoteRunner(conn).run(spec, local_dir / spec.bundle_id)

    if not res.cleanup.clean:
        host.cleanup_ok = False
        host.cleanup_leftovers += list(res.cleanup.leftovers) + list(res.cleanup.errors)
        progress(STAGE_CLEANUP_FAILED)
    elif host.cleanup_ok is None:
        host.cleanup_ok = True

    execu = ExecutionInfo(duration_ms=res.duration_ms, exit_code=res.exit_code,
                          executor="ssh", started_at=started)

    def fail(msg: str) -> list[CheckResult]:
        host.error = f"{host.error}; " if host.error else ""
        host.error += f"[{spec.bundle_id}] {msg}"
        # provides 선언분은 누락으로 드러난다(조용히 사라지지 않게)
        results, _ = normalize([], provides=provides, bundle_id=spec.bundle_id, execution=execu)
        return results

    if res.timed_out:
        host.error = (host.error + "; " if host.error else "") + f"[{spec.bundle_id}] 실행 시간 초과 ({spec.timeout}s)"
    if res.error and not res.collected:
        return fail(res.error)
    if not res.collected:
        return fail("산출물을 회수하지 못했습니다")

    progress(STAGE_COLLECT)
    try:
        files = safe_extract(res.archive_local, local_dir / spec.bundle_id / "extracted")  # type: ignore[arg-type]
    except (tarfile.TarError, OSError) as e:
        return fail(f"산출물 해제 실패: {e}")

    progress(STAGE_PARSE)
    findings = []
    warns: list[str] = []
    for f in sorted(files):
        if f.name.startswith("__"):           # __stdout.log 등 러너 내부 파일
            continue
        pr = parse_artifact(f, bundle_id=spec.bundle_id, profiles=profiles)
        if pr is None:
            continue
        warns.extend(pr.warnings)
        if pr.error:
            warns.append(f"{f.name}: {pr.error}")
            continue
        findings.extend(pr.findings)

    results, orphans = normalize(findings, provides=provides, bundle_id=spec.bundle_id,
                                 execution=execu, manual_rules=manual_rules)
    host.orphan_findings += orphans
    if not findings:
        return fail("산출물에서 판정 결과를 찾지 못했습니다" + (f" ({'; '.join(warns[:3])})" if warns else ""))
    return results


def scan_host(
    conn: Connection,
    job: HostJob,
    local_dir: Path,
    *,
    host_id: str,
    hostname: str,
    address: str | None = None,
    profiles: list[Profile] | None = None,
    progress: Progress = _noop,
    should_cancel: Callable[[], bool] = lambda: False,
) -> HostResult:
    started = datetime.now(UTC)
    host = HostResult(host_id=host_id, hostname=hostname, address=address)
    results: list[CheckResult] = []

    try:
        progress(STAGE_CONNECT)
        conn.connect()

        progress(STAGE_PROBE)
        try:
            host.environment = conn.probe()
        except Exception as e:  # noqa: BLE001 - probe 실패가 진단 전체를 죽이지 않게
            host.environment = RemoteEnvironment(incomplete=True, notes=[f"probe 실패: {e}"])

        for spec, provides in job.bundles:
            if should_cancel():
                host.error = "사용자 취소"
                break
            results += _run_bundle(conn, spec, provides, local_dir, profiles=profiles,
                                   manual_rules=job.manual_rules, started=started,
                                   progress=progress, host=host)

        if job.native and not should_cancel():
            progress(STAGE_NATIVE)
            findings, errors = run_native(
                conn, host.environment, job.native,
                progress=lambda rid, i, n: progress(f"{STAGE_NATIVE} {rid} ({i}/{n})"),
                should_cancel=should_cancel,
            )
            nres, _ = normalize(findings, bundle_id="native", manual_rules=job.manual_rules,
                                execution=ExecutionInfo(executor="ssh-native", started_at=started))
            results += nres + errors

        if job.exclude:
            results = [r for r in results if r.rule_id not in job.exclude]
        results.sort(key=lambda r: (r.source.bundle_id or "", _sort_key(r.rule_id)))
        host.results = results

        if not results and not host.error:
            host.error = "수행할 번들/룰이 없습니다 (프로파일 확인)"
        if not should_cancel():
            progress(STAGE_DONE)
    except Exception as e:  # noqa: BLE001 - 호스트 실패 격리. 절대 밖으로 던지지 않는다
        host.error = f"{type(e).__name__}: {e}"
        log.exception("scan_host 실패 host=%s", host_id)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001,S110
            pass

    return host
