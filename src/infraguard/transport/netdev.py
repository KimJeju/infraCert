"""네트워크 장비 Connection — SSH 대화형 셸(invoke_shell)로 show 명령만 실행.

장비 CLI 는 exec 채널이 없는 경우가 많아 셸을 열고 프롬프트를 기다리는 방식으로 읽는다.
연결 직후 `show version` 으로 벤더를 알아내고 그 벤더의 페이징 해제 명령만 보낸다(엉뚱한 명령을 던지지 않는다).
`show running-config` 류는 세션 내 캐시 — 룰 38개가 같은 설정을 다시 받지 않게.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from infraguard.core.models import RemoteEnvironment
from infraguard.credentials.session import Credential
from infraguard.transport.base import CleanupReport, Connection, ExecResult, TransportError
from infraguard.transport.local import decode_output

DEFAULT_PORT = 22
READ_TIMEOUT = 20
PROMPT_RE = re.compile(r"[\w.@()\-:/]{1,64}[>#]")      # Router>  Router#  user@host>  host(config)#  — 마지막 줄 전체 매치
VENDORS = {                       # os 이름 → (show version 매치, 페이징 해제, 설정 명령)
    "cisco-ios": (re.compile(r"Cisco IOS|IOS-XE|IOS XE|Cisco Nexus|NX-OS", re.I), "terminal length 0"),
    "junos": (re.compile(r"JUNOS|Junos", re.I), "set cli screen-length 0"),
}
CACHEABLE = ("show running-config", "show run", "show configuration", "show startup-config")
INVALID_RE = re.compile(r"% (Invalid|Ambiguous|Incomplete)|syntax error|unknown command", re.I)


@dataclass(slots=True)
class NetdevTarget:
    host: str
    port: int = DEFAULT_PORT
    credential: Credential | None = None


class NetdevConnection(Connection):
    def __init__(self, target: NetdevTarget, *, approve_host_key=None) -> None:  # noqa: ANN001
        self.target = target
        self._approve = approve_host_key
        self._client = None
        self._chan = None                      # 테스트에서 가짜 채널 주입 가능
        self._env: RemoteEnvironment | None = None
        self._cache: dict[str, str] = {}
        self.os: str | None = None

    # ------------------------------------------------------------------ 연결
    def connect(self) -> None:
        import paramiko  # noqa: PLC0415

        from infraguard.transport.hostkey import SessionHostKeyPolicy  # noqa: PLC0415

        cred = self.target.credential
        if cred is None or cred.kind != "password" or cred.password is None:
            raise TransportError("장비 접속은 비밀번호 인증만 지원합니다")
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(SessionHostKeyPolicy(self._approve))
        self._client.connect(self.target.host, port=self.target.port, username=cred.username,
                             password=cred.password.reveal(),          # transport 계층 전용
                             look_for_keys=False, allow_agent=False, timeout=15, auth_timeout=15, banner_timeout=15)
        self._chan = self._client.invoke_shell(width=511, height=1000)
        self._chan.settimeout(1.0)
        self._init_session()

    def _init_session(self) -> None:
        """배너·첫 프롬프트를 비우고 벤더 판별 후 페이징 해제."""
        self._read_until_prompt(READ_TIMEOUT)
        ver = self._run("show version")
        for name, (pat, nopage) in VENDORS.items():
            if pat.search(ver):
                self.os = name
                self._run(nopage)
                break
        self._version_text = ver

    # ------------------------------------------------------------------ 입출력
    def _read_until_prompt(self, timeout: float) -> tuple[str, bool]:
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = self._chan.recv(65535)
            except Exception:  # noqa: BLE001 - socket timeout 등: 잠깐 쉬고 다시
                chunk = b""
            if chunk:
                buf += chunk
                text, _ = decode_output(buf)
                if _ends_with_prompt(text):
                    return text, False
            else:
                time.sleep(0.05)
        text, _ = decode_output(buf)
        return text, True

    def _run(self, cmd: str, timeout: float = READ_TIMEOUT) -> str:
        self._chan.send(cmd + "\n")
        text, _ = self._read_until_prompt(timeout)
        return _strip_echo(text, cmd)

    def exec(self, argv: list[str], *, timeout: int, cwd: str | None = None,
             stdin_data: str | None = None, max_output: int = 1 << 20) -> ExecResult:
        if self._chan is None:
            raise TransportError("not connected")
        cmd = argv[-1].strip()
        started = time.monotonic()
        key = cmd.lower()
        if key in self._cache:
            return ExecResult(argv, 0, self._cache[key], "", 0)
        self._chan.send(cmd + "\n")
        text, timed_out = self._read_until_prompt(timeout)
        out = _strip_echo(text, cmd)[:max_output]
        ms = int((time.monotonic() - started) * 1000)
        if timed_out:
            return ExecResult(argv, None, out, "", ms, timed_out=True)
        if INVALID_RE.search(out):
            return ExecResult(argv, 1, "", out, ms)
        if key.startswith(CACHEABLE):
            self._cache[key] = out
        return ExecResult(argv, 0, out, "", ms)

    # ------------------------------------------------------------------ 환경
    def probe(self) -> RemoteEnvironment:
        if self._env is not None:
            return self._env
        ver = getattr(self, "_version_text", "") or ""
        m = re.search(r"Version\s+([\w.()\[\]-]+)", ver) or re.search(r"Junos:\s*(\S+)", ver)
        notes = [] if self.os else [f"벤더 미식별(show version): {ver[:80]!r}"]
        self._env = RemoteEnvironment(os=self.os, os_version=m.group(1) if m else None,
                                      hostname=_prompt_host(ver), incomplete=not self.os, notes=notes)
        return self._env

    def upload(self, local: Path, remote: str) -> None:
        raise TransportError("netdev: 업로드 없음")

    def download(self, remote: str, local: Path) -> None:
        raise TransportError("netdev: 다운로드 없음")

    def cleanup(self, paths: list[str]) -> CleanupReport:
        return CleanupReport(requested=list(paths), leftovers=list(paths))

    def close(self) -> None:
        try:
            if self._chan is not None:
                self._chan.close()
            if self._client is not None:
                self._client.close()
        finally:
            self._chan = self._client = None


def _ends_with_prompt(text: str) -> bool:
    last = text.rstrip().rsplit("\n", 1)[-1].strip()
    return bool(last) and PROMPT_RE.fullmatch(last) is not None


def _strip_echo(text: str, cmd: str) -> str:
    """에코된 명령 줄과 마지막 프롬프트 줄을 뗀다."""
    lines = text.replace("\r", "").split("\n")
    while lines and not lines[0].strip():
        lines = lines[1:]
    if lines and lines[0].strip().endswith(cmd):
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    if lines and PROMPT_RE.fullmatch(lines[-1].strip()):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


def _prompt_host(text: str) -> str | None:
    m = re.search(r"(?m)^([\w.@\-]{1,64})[>#]\s*$", text)
    return m.group(1) if m else None
