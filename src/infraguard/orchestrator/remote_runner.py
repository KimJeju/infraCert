"""원격 Bundle 실행기.

시퀀스:
    1. 원격 격리 디렉터리 생성 (mktemp -d)   -> CWD 오염 방지
    2. 스크립트 업로드
    3. nohup 백그라운드 실행 + 완료마커 폴링  -> 세션 끊겨도 진단 유지 (TMOUT 대응)
    4. 산출물 tar.gz 묶어 회수
    5. 원격 정리 + 삭제 검증               -> 흔적 미잔류

전 과정에서 명령은 argv 배열로 조립한다. 셸 문자열 결합 금지.
"""

from __future__ import annotations

import logging
import posixpath
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path

from infraguard.transport.base import CleanupReport, Connection, ExecResult

log = logging.getLogger(__name__)

MARKER = "__infraguard_done__"
STDOUT_LOG = "__stdout.log"
STDERR_LOG = "__stderr.log"
ARCHIVE = "__collect.tar.gz"

POLL_INTERVAL_START = 2.0
POLL_INTERVAL_MAX = 15.0


@dataclass(slots=True)
class RunSpec:
    bundle_id: str
    script: Path                     # 로컬 스크립트 경로
    args: list[str] = field(default_factory=list)
    timeout: int = 1800              # 기본 30분 (find / 순회 스크립트 대응)
    interpreter: str | None = None   # None 이면 shebang 사용
    collect_globs: list[str] = field(default_factory=lambda: ["*"])
    extra_files: list[Path] = field(default_factory=list)   # 동반 업로드(예: oracle .sql)
    env: dict[str, str] = field(default_factory=dict)       # 스크립트 파라미터(TOMCAT_HOME 등). 원격 환경변수로 전달


# 환경변수 이름/값 허용 문자. 셸 인용부호를 피해 원격 명령 조립을 단순·안전하게 유지한다(인젝션 원천 차단).
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_ENV_VALUE_RE = re.compile(r"^[A-Za-z0-9_./:@%+=,-]*$")


def validate_env(env: dict[str, str]) -> None:
    """허용되지 않은 문자가 있으면 ValueError. 조용히 잘라내지 않는다."""
    for k, v in env.items():
        if not _ENV_NAME_RE.match(k):
            raise ValueError(f"파라미터 이름 형식 오류: {k!r} (대문자·숫자·_ 만)")
        if not _ENV_VALUE_RE.match(v):
            raise ValueError(f"파라미터 {k} 값에 허용되지 않은 문자: {v!r} (경로·식별자 문자만 허용)")


@dataclass(slots=True)
class RunResult:
    bundle_id: str
    remote_dir: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    error: str = ""
    archive_local: Path | None = None
    cleanup: CleanupReport = field(default_factory=CleanupReport)

    @property
    def collected(self) -> bool:
        return self.archive_local is not None and self.archive_local.exists()


class RemoteRunner:
    def __init__(self, conn: Connection) -> None:
        self.conn = conn

    # ------------------------------------------------------------------ public
    def run(self, spec: RunSpec, local_dest: Path) -> RunResult:
        res = RunResult(bundle_id=spec.bundle_id)
        t0 = time.monotonic()

        remote_dir = self._make_workdir()
        if remote_dir is None:
            res.error = "failed to create remote work directory"
            return res
        res.remote_dir = remote_dir

        try:
            self._upload(spec, remote_dir)
            started = self._launch(spec, remote_dir)
            if started.error:
                res.error = started.error
                return res

            ok = self._wait(remote_dir, spec.timeout)
            res.timed_out = not ok

            res.exit_code = self._read_exit_code(remote_dir)
            res.stdout = self._tail(posixpath.join(remote_dir, STDOUT_LOG))
            res.stderr = self._tail(posixpath.join(remote_dir, STDERR_LOG))

            if res.timed_out:
                self._kill(remote_dir)

            archive = self._collect(spec, remote_dir)
            if archive:
                local = local_dest / f"{spec.bundle_id}{ARCHIVE}"
                self.conn.download(archive, local)
                res.archive_local = local
        except Exception as e:  # noqa: BLE001
            res.error = f"{type(e).__name__}: {e}"
        finally:
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            # 실패해도 반드시 정리를 시도한다. 아카이브는 작업디렉터리 밖에 있으므로 함께 지운다.
            res.cleanup = self.conn.cleanup([remote_dir, remote_dir + ".tar.gz"])
            if not res.cleanup.clean:
                log.warning(
                    "원격 정리 미완료 bundle=%s leftovers=%s errors=%s",
                    spec.bundle_id, res.cleanup.leftovers, res.cleanup.errors,
                )
        return res

    # ----------------------------------------------------------------- private
    def _make_workdir(self) -> str | None:
        # mktemp -d 우선. 없거나 실패하면 PID+시각 기반 fallback (AIX/HP-UX 대응)
        script = (
            'd=$(mktemp -d /tmp/infraguard-XXXXXX 2>/dev/null) || '
            'd=/tmp/infraguard-$$-$(date +%Y%m%d%H%M%S); '
            'mkdir -p "$d" 2>/dev/null; chmod 700 "$d" 2>/dev/null; printf %s "$d"'
        )
        r = self.conn.exec(["sh", "-c", script], timeout=30)
        d = r.stdout.strip()
        if not r.ok or not d.startswith("/tmp/infraguard-"):
            log.error("workdir creation failed: %s / %s", r.stdout, r.stderr)
            return None
        return d

    def _upload(self, spec: RunSpec, remote_dir: str) -> None:
        remote_script = posixpath.join(remote_dir, spec.script.name)
        self.conn.upload(spec.script, remote_script)
        self.conn.exec(["chmod", "700", remote_script], timeout=30)
        for extra in spec.extra_files:
            self.conn.upload(extra, posixpath.join(remote_dir, extra.name))

    def _launch(self, spec: RunSpec, remote_dir: str) -> ExecResult:
        script_path = posixpath.join(remote_dir, spec.script.name)
        validate_env(spec.env)                       # 허용 문자만 통과했으므로 인용 없이 안전
        env_prefix = "".join(f"{k}={v} " for k, v in spec.env.items())
        tail = " ".join(shlex.quote(a) for a in [script_path, *spec.args])
        it = spec.interpreter
        if it and it != "sh" and "/" not in it:
            # 선언한 인터프리터(ksh 등)가 대상에 없으면 exit 127 로 빈 산출물이 된다(09-12 Oracle 컨테이너).
            # 스크립트가 POSIX 라면 sh 로도 돈다 — 대체 실행하되 사유를 stderr 에 남겨 결과에서 보이게 한다.
            inner = (f"if command -v {it} >/dev/null 2>&1; then {env_prefix}{it} {tail}; "
                     f"else echo \"[infraguard] interpreter {it} not found - falling back to sh\" >&2; "
                     f"{env_prefix}sh {tail}; fi")
        else:
            inner = env_prefix + (f"{it} " if it else "") + tail

        # nohup 백그라운드 + 완료 마커. 세션이 끊겨도 계속 실행된다.
        runner = (
            f"cd {shlex.quote(remote_dir)} && "
            f"nohup sh -c '{inner} > {STDOUT_LOG} 2> {STDERR_LOG}; "
            f'echo $? > {MARKER}\' > /dev/null 2>&1 & echo $!'
        )
        return self.conn.exec(["sh", "-c", runner], timeout=60)

    def _wait(self, remote_dir: str, timeout: int) -> bool:
        marker = posixpath.join(remote_dir, MARKER)
        deadline = time.monotonic() + timeout
        interval = POLL_INTERVAL_START
        while time.monotonic() < deadline:
            r = self.conn.exec(
                ["sh", "-c", f"test -f {shlex.quote(marker)} && echo DONE || echo WAIT"],
                timeout=30,
            )
            if "DONE" in r.stdout:
                return True
            time.sleep(interval)
            interval = min(interval * 1.5, POLL_INTERVAL_MAX)
        return False

    def _read_exit_code(self, remote_dir: str) -> int | None:
        marker = posixpath.join(remote_dir, MARKER)
        r = self.conn.exec(["sh", "-c", f"cat {shlex.quote(marker)} 2>/dev/null"], timeout=30)
        raw = r.stdout.strip()
        return int(raw) if raw.isdigit() else None

    def _tail(self, remote_file: str, lines: int = 200) -> str:
        r = self.conn.exec(
            ["sh", "-c", f"tail -n {lines} {shlex.quote(remote_file)} 2>/dev/null"],
            timeout=30,
        )
        return r.stdout

    def _kill(self, remote_dir: str) -> None:
        """타임아웃 시 해당 작업 디렉터리를 쓰는 프로세스를 정리한다."""
        self.conn.exec(
            ["sh", "-c",
             f"pkill -f {shlex.quote(remote_dir)} 2>/dev/null || true"],
            timeout=30,
        )

    def _collect(self, spec: RunSpec, remote_dir: str) -> str | None:
        """산출물을 묶는다.

        아카이브를 작업 디렉터리 *밖*(형제 경로)에 만든다.
        디렉터리 안에 만들면 tar 가 자기 자신을 포함하는 문제가 생긴다.
        업로드한 우리 스크립트는 회수 대상이 아니므로 제외한다.
        """
        archive = remote_dir + ".tar.gz"
        excls = " ".join(
            f"--exclude={shlex.quote('./' + p.name)}" for p in [spec.script, *spec.extra_files]
        )
        cmd = (
            f"cd {shlex.quote(remote_dir)} && "
            f"tar czf {shlex.quote(archive)} {excls} . 2>/dev/null "
            f"|| tar czf {shlex.quote(archive)} . 2>/dev/null; "
            f"test -f {shlex.quote(archive)} && echo OK"
        )
        r = self.conn.exec(["sh", "-c", cmd], timeout=600)
        return archive if "OK" in r.stdout else None
