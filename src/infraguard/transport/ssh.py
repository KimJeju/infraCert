"""SSH/SFTP transport.

- 1단 bastion(ProxyJump) 지원
- 호스트키 검증 필수 (AutoAddPolicy 금지), known_hosts 파일 미생성
- 명령은 argv 배열로 받아 shlex.quote 로 조립한다. 문자열 결합 금지
- 출력 상한·타임아웃·인코딩 폴백
- cleanup 은 삭제 후 검증한다
"""

from __future__ import annotations

import logging
import posixpath
import shlex
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from infraguard.core.models import RemoteEnvironment
from infraguard.credentials.session import Credential
from infraguard.transport.base import (
    CleanupReport,
    Connection,
    ExecResult,
    TransportError,
)
from infraguard.transport.hostkey import ApprovalCallback, SessionHostKeyPolicy

log = logging.getLogger(__name__)

DEFAULT_PORT = 22
CONNECT_TIMEOUT = 15
KEEPALIVE = 30

# probe 에서 확인할 명령들
PROBE_COMMANDS = (
    "awk", "grep", "sed", "ps", "find", "tar", "id", "uname",
    "sudo", "getent", "stat", "sqlplus", "mysql", "psql",
)


@dataclass(slots=True)
class SSHTarget:
    host: str
    port: int = DEFAULT_PORT
    credential: Credential | None = None


class SSHConnection(Connection):
    def __init__(
        self,
        target: SSHTarget,
        *,
        bastion: SSHTarget | None = None,
        approve_host_key: ApprovalCallback | None = None,
        policy: SessionHostKeyPolicy | None = None,
    ) -> None:
        self.target = target
        self.bastion = bastion
        self._policy = policy or SessionHostKeyPolicy(approve_host_key)
        self._client: paramiko.SSHClient | None = None
        self._bastion_client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None
        self._env: RemoteEnvironment | None = None

    # ------------------------------------------------------------------ connect
    def _make_client(self) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        # 파일 기반 known_hosts 를 읽지도 쓰지도 않는다 (고객사 PC 잔류물 방지)
        c.set_missing_host_key_policy(self._policy)
        return c

    @staticmethod
    def _auth_kwargs(cred: Credential | None) -> dict[str, object]:
        if cred is None:
            raise TransportError("credential is required")
        kw: dict[str, object] = {
            "username": cred.username,
            "allow_agent": cred.kind == "agent",
            "look_for_keys": False,
            "timeout": CONNECT_TIMEOUT,
            "auth_timeout": CONNECT_TIMEOUT,
            "banner_timeout": CONNECT_TIMEOUT,
        }
        if cred.kind == "password":
            if cred.password is None:
                raise TransportError("password is required")
            kw["password"] = cred.password.reveal()      # transport 계층 전용
        elif cred.kind == "key":
            if not cred.key_path:
                raise TransportError("key_path is required")
            kw["key_filename"] = cred.key_path
            if cred.key_passphrase is not None:
                kw["passphrase"] = cred.key_passphrase.reveal()
        return kw

    def connect(self) -> None:
        sock: paramiko.Channel | None = None

        if self.bastion is not None:
            self._bastion_client = self._make_client()
            self._bastion_client.connect(
                self.bastion.host, port=self.bastion.port,
                **self._auth_kwargs(self.bastion.credential),  # type: ignore[arg-type]
            )
            transport = self._bastion_client.get_transport()
            if transport is None:
                raise TransportError("bastion transport unavailable")
            transport.set_keepalive(KEEPALIVE)
            sock = transport.open_channel(
                "direct-tcpip",
                dest_addr=(self.target.host, self.target.port),
                src_addr=("127.0.0.1", 0),
            )

        self._client = self._make_client()
        self._client.connect(
            self.target.host, port=self.target.port, sock=sock,
            **self._auth_kwargs(self.target.credential),  # type: ignore[arg-type]
        )
        t = self._client.get_transport()
        if t is not None:
            t.set_keepalive(KEEPALIVE)

    def _require(self) -> paramiko.SSHClient:
        if self._client is None:
            raise TransportError("not connected")
        return self._client

    # --------------------------------------------------------------------- exec
    def exec(
        self, argv: list[str], *, timeout: int, cwd: str | None = None,
        stdin_data: str | None = None, max_output: int = 1 << 20,
        force_c_locale: bool = True,
    ) -> ExecResult:
        client = self._require()
        cmd = " ".join(shlex.quote(a) for a in argv)
        if cwd:
            cmd = f"cd {shlex.quote(cwd)} && {cmd}"
        if force_c_locale:
            # 명령 출력이 로케일에 따라 달라지는 것을 막는다.
            # 단 probe 의 로케일 조회는 예외 (시스템 실제 값을 봐야 한다).
            cmd = f"LANG=C LC_ALL=C {cmd}"

        started = time.monotonic()
        try:
            chan = client.get_transport().open_session()  # type: ignore[union-attr]
        except Exception as e:  # noqa: BLE001
            return ExecResult(argv, None, "", "", 0, error=f"session open failed: {e}")

        chan.settimeout(float(timeout))
        out_buf = bytearray()
        err_buf = bytearray()
        out_cut = err_cut = False
        timed_out = False

        try:
            chan.exec_command(cmd)
            if stdin_data is not None:
                chan.sendall(stdin_data.encode())
            chan.shutdown_write()

            deadline = time.monotonic() + timeout
            while True:
                if chan.recv_ready():
                    b = chan.recv(32768)
                    if len(out_buf) < max_output:
                        out_buf += b
                    else:
                        out_cut = True
                if chan.recv_stderr_ready():
                    b = chan.recv_stderr(32768)
                    if len(err_buf) < max_output:
                        err_buf += b
                    else:
                        err_cut = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.01)
        except socket.timeout:
            timed_out = True
        except Exception as e:  # noqa: BLE001
            return ExecResult(
                argv, None, "", "", int((time.monotonic() - started) * 1000),
                error=f"exec failed: {e}",
            )

        exit_code: int | None = None
        if timed_out:
            try:
                chan.close()
            except Exception:  # noqa: BLE001,S110
                pass
        else:
            exit_code = chan.recv_exit_status()
            chan.close()

        stdout, enc_err1 = _decode(bytes(out_buf))
        stderr, enc_err2 = _decode(bytes(err_buf))
        return ExecResult(
            argv=argv, exit_code=exit_code, stdout=stdout, stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=timed_out, stdout_truncated=out_cut, stderr_truncated=err_cut,
            encoding_error=enc_err1 or enc_err2,
        )

    # -------------------------------------------------------------------- probe
    def probe(self) -> RemoteEnvironment:
        if self._env is not None:
            return self._env

        notes: list[str] = []

        def one(argv: list[str]) -> str | None:
            r = self.exec(argv, timeout=15)
            if r.ok and r.stdout.strip():
                return r.stdout.strip()
            return None

        uname_s = one(["uname", "-s"])
        uname_r = one(["uname", "-r"])
        uname_m = one(["uname", "-m"])
        hostname = one(["uname", "-n"])
        user = one(["id", "-un"])
        uid = one(["id", "-u"])
        shell = one(["sh", "-c", "echo $SHELL"])
        # 시스템 실제 로케일. LANG=C 강제를 풀고 조회한다.
        rloc = self.exec(
            ["sh", "-c", "locale charmap 2>/dev/null || echo unknown"],
            timeout=15, force_c_locale=False,
        )
        locale_out = rloc.stdout.strip() if rloc.ok else None
        rlang = self.exec(
            ["sh", "-c", 'printf %s "${LANG:-}"'], timeout=15, force_c_locale=False,
        )
        lang_val = rlang.stdout.strip() if rlang.ok else ""

        os_name = _normalize_os(uname_s)
        if os_name is None:
            notes.append(f"unrecognized uname -s: {uname_s!r}")

        # 배포판 상세
        os_version = uname_r
        rel = one(["sh", "-c", "cat /etc/os-release 2>/dev/null | head -20"])
        if rel:
            for line in rel.splitlines():
                if line.startswith("PRETTY_NAME="):
                    os_version = line.split("=", 1)[1].strip().strip('"')
                    break

        cmds: dict[str, bool] = {}
        probe_sh = "; ".join(
            f'command -v {shlex.quote(c)} >/dev/null 2>&1 && echo "{c}=1" || echo "{c}=0"'
            for c in PROBE_COMMANDS
        )
        r = self.exec(["sh", "-c", probe_sh], timeout=30)
        if r.ok:
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    cmds[k.strip()] = v.strip() == "1"
        else:
            notes.append("command probe failed")

        env = RemoteEnvironment(
            os=os_name,
            os_version=os_version,
            architecture=uname_m,
            hostname=hostname,
            user=user,
            privileged=(uid == "0") if uid is not None else None,
            shell=shell if shell and shell != "$SHELL" else None,
            locale=lang_val or locale_out,
            encoding=_charmap_to_encoding(locale_out),
            available_commands=cmds,
            incomplete=bool(notes) or os_name is None,
            notes=notes,
        )
        self._env = env
        return env

    # ------------------------------------------------------------------- sftp
    def _sftp_client(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            self._sftp = self._require().open_sftp()
        return self._sftp

    def upload(self, local: Path, remote: str) -> None:
        self._sftp_client().put(str(local), remote)

    def download(self, remote: str, local: Path) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        self._sftp_client().get(remote, str(local))

    def listdir(self, remote: str) -> list[str]:
        try:
            return self._sftp_client().listdir(remote)
        except OSError:
            return []

    def listdir_attr(self, remote: str) -> list[tuple[str, int, bool, int]]:
        """(이름, 크기, 디렉터리여부, mtime). 파일 브라우저(§8)용."""
        import stat as _st
        out = []
        for a in self._sftp_client().listdir_attr(remote):
            is_dir = bool(a.st_mode and _st.S_ISDIR(a.st_mode))
            out.append((a.filename, int(a.st_size or 0), is_dir, int(a.st_mtime or 0)))
        return sorted(out, key=lambda t: (not t[2], t[0].lower()))

    def remove(self, remote: str) -> None:
        """원격 파일 1개 삭제. 디렉터리는 삭제하지 않는다(파일 브라우저는 파일만)."""
        if not _safe_remote_path(remote):
            raise TransportError(f"refused (unsafe path): {remote}")
        self._sftp_client().remove(remote)

    def download_progress(self, remote: str, local: Path, cb) -> None:  # noqa: ANN001
        local.parent.mkdir(parents=True, exist_ok=True)
        self._sftp_client().get(remote, str(local), callback=cb)

    def upload_progress(self, local: Path, remote: str, cb) -> None:  # noqa: ANN001
        self._sftp_client().put(str(local), remote, callback=cb)

    # ------------------------------------------------------------------ shell
    def open_shell(self, cols: int = 120, rows: int = 32) -> paramiko.Channel:
        """대화형 셸(pty). 터미널 탭(§7)용. 읽기 루프는 호출측 워커가 돌린다."""
        chan = self._require().invoke_shell(term="xterm-256color", width=cols, height=rows)
        chan.settimeout(0.0)   # 논블로킹 recv
        return chan

    # ---------------------------------------------------------------- cleanup
    def cleanup(self, paths: list[str]) -> CleanupReport:
        """원격 산출물 삭제 후 검증한다. 조용히 남기지 않는다."""
        rep = CleanupReport(requested=list(paths))
        for p in paths:
            if not _safe_remote_path(p):
                rep.errors.append(f"{p}: refused (unsafe path)")
                continue
            r = self.exec(["rm", "-rf", "--", p], timeout=60)
            if r.error or r.timed_out:
                rep.errors.append(f"{p}: {r.error or 'timeout'}")
                continue
            chk = self.exec(["sh", "-c", f"test -e {shlex.quote(p)} && echo EXISTS || echo GONE"],
                            timeout=30)
            if "GONE" in chk.stdout:
                rep.removed.append(p)
            else:
                rep.leftovers.append(p)
        return rep

    # ------------------------------------------------------------------ close
    def close(self) -> None:
        for obj in (self._sftp, self._client, self._bastion_client):
            try:
                if obj is not None:
                    obj.close()
            except Exception:  # noqa: BLE001,S110
                pass
        self._sftp = None
        self._client = None
        self._bastion_client = None


# ---------------------------------------------------------------------- helpers
_DANGEROUS = {"/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/home", "/root", "/opt", "/tmp"}


def _safe_remote_path(p: str) -> bool:
    """삭제해도 되는 경로인가. 최소한의 안전장치."""
    if not p or not p.startswith("/"):
        return False
    norm = posixpath.normpath(p)
    if norm in _DANGEROUS or norm == "/":
        return False
    if ".." in norm.split("/"):
        return False
    # 최소 3단계 이상 (예: /tmp/infraguard-xxxx)
    return len([x for x in norm.split("/") if x]) >= 2


def _decode(b: bytes) -> tuple[str, bool]:
    for enc in ("utf-8", "cp949", "euc-kr"):
        try:
            return b.decode(enc), False
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace"), True


def _normalize_os(uname_s: str | None) -> str | None:
    if not uname_s:
        return None
    s = uname_s.strip().lower()
    return {
        "linux": "linux", "aix": "aix", "sunos": "solaris",
        "hp-ux": "hpux", "darwin": "darwin", "freebsd": "freebsd",
    }.get(s)


def _charmap_to_encoding(charmap: str | None) -> str | None:
    if not charmap:
        return None
    c = charmap.strip().upper()
    return {"UTF-8": "utf-8", "ANSI_X3.4-1968": "ascii", "EUC-KR": "euc-kr",
            "CP949": "cp949", "UNKNOWN": None}.get(c, c.lower())
