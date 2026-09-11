"""로컬 실행 Connection — 이 PC 자체를 점검하거나(PC-xx), 룰을 실기기 없이 검증할 때.

원격 개념이 없으므로 upload/download 는 거부하고 cleanup 은 아무것도 지우지 않는다.
"""

from __future__ import annotations

import getpass
import platform
import subprocess
import sys
import time
from pathlib import Path

from infraguard.core.models import RemoteEnvironment
from infraguard.transport import psbatch
from infraguard.transport.base import CleanupReport, Connection, ExecResult, TransportError

# 출력 인코딩은 건드리지 않는다: UTF-8 로 강제하면 w32tm 같은 네이티브 도구(OEM cp949)가 깨진다.
# 콘솔 기본(cp949)으로 일관되게 받고 decode_output 이 utf-8→cp949 순으로 푼다.
_PS_PRELUDE = "$ProgressPreference='SilentlyContinue'; "


def decode_output(b: bytes) -> tuple[str, bool]:
    for enc in ("utf-8", "cp949"):
        try:
            return b.decode(enc), False
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace"), True


class LocalConnection(Connection):
    def __init__(self) -> None:
        self._env: RemoteEnvironment | None = None
        self._prefetched: dict[str, tuple[str, int]] = {}   # cmd → (stdout, rc), 배치 프리페치 결과

    def prefetch_powershell(self, cmds: list[str]) -> None:
        """수집 명령을 powershell 프로세스 1회로 묶어 실행(WinRM 과 같은 스크립트·파서 — 여기서 실검증된다)."""
        r = self.exec(["powershell", "-NoProfile", "-NonInteractive", "-Command", psbatch.build_script(cmds)], timeout=600)
        for cmd, (body, rc) in psbatch.parse_output(r.stdout, cmds).items():
            self._prefetched[cmd] = (body, rc)

    def connect(self) -> None:
        return None

    def probe(self) -> RemoteEnvironment:
        if self._env is None:
            sysname = platform.system().lower()
            self._env = RemoteEnvironment(
                os="windows" if sysname == "windows" else sysname or None,
                os_version=platform.version() or None, architecture=platform.machine() or None,
                hostname=platform.node() or None, user=getpass.getuser() or None,
            )
        return self._env

    def exec(self, argv: list[str], *, timeout: int, cwd: str | None = None,
             stdin_data: str | None = None, max_output: int = 1 << 20) -> ExecResult:
        argv = list(argv)
        if argv and argv[0].lower() == "powershell" and argv[-1] in self._prefetched:
            body, rc = self._prefetched.pop(argv[-1])
            return ExecResult(argv, rc, body, "", 0)
        if argv and argv[0].lower() == "powershell" and len(argv) >= 2:
            argv[-1] = _PS_PRELUDE + argv[-1]
        started = time.monotonic()
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd,  # noqa: S603 - 룰 명령은 상수, 셸 경유 없음
                               input=stdin_data.encode() if stdin_data else None)
        except subprocess.TimeoutExpired:
            return ExecResult(argv, None, "", "", int((time.monotonic() - started) * 1000), timed_out=True)
        except (OSError, ValueError) as e:
            return ExecResult(argv, None, "", "", int((time.monotonic() - started) * 1000), error=f"exec failed: {e}")
        out, e1 = decode_output(p.stdout[:max_output])
        err, e2 = decode_output(p.stderr[:max_output])
        return ExecResult(argv, p.returncode, out, err, int((time.monotonic() - started) * 1000),
                          stdout_truncated=len(p.stdout) > max_output, stderr_truncated=len(p.stderr) > max_output,
                          encoding_error=e1 or e2)

    def upload(self, local: Path, remote: str) -> None:
        raise TransportError("local: 업로드 없음")

    def download(self, remote: str, local: Path) -> None:
        raise TransportError("local: 다운로드 없음")

    def cleanup(self, paths: list[str]) -> CleanupReport:
        # 원격 격리 디렉터리가 없으므로 지울 것도 없다. 요청이 있었다면 남았다고 정직하게 보고.
        return CleanupReport(requested=list(paths), leftovers=list(paths))

    def close(self) -> None:
        return None


def is_windows() -> bool:
    return sys.platform.startswith("win")
