"""WinRM Connection — Windows 서버/PC 를 PowerShell 원격으로 읽기전용 점검.

pywinrm 세션. 비밀번호 인증(NTLM 기본, 5986 이면 TLS). 파일 전송은 지원하지 않는다(네이티브 룰 전용).
reveal() 은 이 계층에서만 호출한다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from infraguard.core.models import RemoteEnvironment
from infraguard.credentials.session import Credential
from infraguard.transport.base import CleanupReport, Connection, ExecResult, TransportError
from infraguard.transport.local import decode_output

DEFAULT_PORT = 5985
OPERATION_TIMEOUT = 60
_PS_PRELUDE = "$ProgressPreference='SilentlyContinue'; "


@dataclass(slots=True)
class WinRMTarget:
    host: str
    port: int = DEFAULT_PORT
    credential: Credential | None = None
    use_ssl: bool = False
    transport: str = "ntlm"          # ntlm | basic | kerberos
    verify_cert: bool = False        # 자체서명이 대부분 — 검증은 옵션


class WinRMConnection(Connection):
    def __init__(self, target: WinRMTarget) -> None:
        self.target = target
        self._session = None
        self._env: RemoteEnvironment | None = None

    def connect(self) -> None:
        import winrm  # noqa: PLC0415 - 선택 의존성(pywinrm)

        cred = self.target.credential
        if cred is None or cred.kind != "password" or cred.password is None:
            raise TransportError("WinRM 은 비밀번호 인증만 지원합니다")
        scheme = "https" if self.target.use_ssl else "http"
        self._session = winrm.Session(
            f"{scheme}://{self.target.host}:{self.target.port}/wsman",
            auth=(cred.username, cred.password.reveal()),          # transport 계층 전용
            transport=self.target.transport,
            server_cert_validation="validate" if self.target.verify_cert else "ignore",
            operation_timeout_sec=OPERATION_TIMEOUT, read_timeout_sec=OPERATION_TIMEOUT + 10,
        )
        r = self.exec(["powershell", "-Command", "$PSVersionTable.PSVersion.Major"], timeout=OPERATION_TIMEOUT)
        if not r.ok:
            raise TransportError(f"WinRM 연결 실패: {r.error or r.stderr.strip()[:200]}")

    def _require(self):  # noqa: ANN202
        if self._session is None:
            raise TransportError("not connected")
        return self._session

    def exec(self, argv: list[str], *, timeout: int, cwd: str | None = None,
             stdin_data: str | None = None, max_output: int = 1 << 20) -> ExecResult:
        s = self._require()
        started = time.monotonic()
        try:
            if argv and argv[0].lower() == "powershell":
                r = s.run_ps(_PS_PRELUDE + argv[-1])
            else:
                r = s.run_cmd(argv[0], argv[1:])
        except Exception as e:  # noqa: BLE001 - 전송 오류는 ERROR 근거로
            return ExecResult(argv, None, "", "", int((time.monotonic() - started) * 1000), error=f"winrm: {e}")
        out, e1 = decode_output(r.std_out[:max_output])
        err, e2 = decode_output(r.std_err[:max_output])
        return ExecResult(argv, r.status_code, out, err, int((time.monotonic() - started) * 1000),
                          stdout_truncated=len(r.std_out) > max_output, stderr_truncated=len(r.std_err) > max_output,
                          encoding_error=e1 or e2)

    def probe(self) -> RemoteEnvironment:
        if self._env is not None:
            return self._env
        r = self.exec(["powershell", "-Command",
                       "$o=Get-CimInstance Win32_OperatingSystem; "
                       "Write-Output ($o.Caption+'|'+$o.Version+'|'+$o.OSArchitecture+'|'+$env:COMPUTERNAME+'|'+$env:USERNAME)"],
                      timeout=OPERATION_TIMEOUT)
        notes: list[str] = []
        parts = (r.stdout.strip().split("|") + [""] * 5)[:5] if r.ok else [""] * 5
        if not r.ok:
            notes.append(f"probe 실패: {r.error or r.stderr.strip()[:120]}")
        self._env = RemoteEnvironment(
            os="windows", os_version=(parts[0] + " " + parts[1]).strip() or None,
            architecture=parts[2] or None, hostname=parts[3] or None, user=parts[4] or None,
            incomplete=not r.ok, notes=notes,
        )
        return self._env

    def upload(self, local: Path, remote: str) -> None:
        raise TransportError("winrm: 파일 업로드 미지원(네이티브 룰 전용)")

    def download(self, remote: str, local: Path) -> None:
        raise TransportError("winrm: 파일 다운로드 미지원")

    def cleanup(self, paths: list[str]) -> CleanupReport:
        return CleanupReport(requested=list(paths), leftovers=list(paths))

    def close(self) -> None:
        self._session = None
