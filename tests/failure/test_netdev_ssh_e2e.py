"""장비 전송 E2E — 실제 SSH(paramiko 서버)로 가짜 Cisco IOS CLI 를 띄우고 NetdevConnection.connect() 전 경로를 태운다.

실장비 없이 검증되는 것: 비밀번호 인증·호스트키 승인 콜백·invoke_shell·배너/프롬프트 대기·벤더 판별·페이징 해제·
show 명령 캐시·잘못된 명령 처리·probe. 실장비와 다른 것: 응답 타이밍, 실제 배너 형식.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import paramiko
import pytest

from infraguard.core.models import RemoteEnvironment
from infraguard.credentials.secret import Secret
from infraguard.credentials.session import Credential
from infraguard.orchestrator.native_runner import run_native
from infraguard.rulepack import loader
from infraguard.transport.base import TransportError
from infraguard.transport.netdev import NetdevConnection, NetdevTarget

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"
RUNNING_CONFIG = """Building configuration...

Current configuration : 1024 bytes
!
version 15.0
service timestamps log datetime msec
service password-encryption
no service pad
hostname FAKE-R1
!
enable secret 5 $1$zzzz$abcdefghijklmnop
!
no ip source-route
no ip bootp server
no cdp run
no ip domain-lookup
no ip http server
no ip http secure-server
logging buffered 64000
logging host 10.10.0.5
ntp server 10.10.0.9
banner login ^C Authorized access only ^C
snmp-server community public RW
line vty 0 4
 exec-timeout 0 0
 transport input telnet
line aux 0
 no exec
!
end"""


class _IOS(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.shell = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("admin", "Cisco#123") else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a) -> bool:  # noqa: ANN002
        return True

    def check_channel_shell_request(self, channel) -> bool:  # noqa: ANN001
        self.shell.set()
        return True


def _serve_cli(chan: paramiko.Channel, log: list[str]) -> None:
    """한 줄씩 받아 IOS 처럼 응답. 페이징(--More--)은 terminal length 0 전까지 켜져 있다."""
    prompt = "FAKE-R1>"
    chan.send("\r\nUser Access Verification\r\n\r\n" + prompt)
    paging = True
    buf = ""
    while True:
        data = chan.recv(1024)
        if not data:
            return
        buf += data.decode(errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            cmd = line.strip()
            log.append(cmd)
            if cmd == "show version":
                body = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\r\nFAKE-R1 uptime is 1 day"
            elif cmd == "terminal length 0":
                paging, body = False, ""
            elif cmd == "show running-config":
                body = RUNNING_CONFIG.replace("\n", "\r\n") + ("\r\n --More-- " if paging else "")
            elif cmd.startswith("show running-config | include "):
                pat = cmd.split("include ", 1)[1]
                import re
                body = "\r\n".join(ln for ln in RUNNING_CONFIG.splitlines() if re.search(pat, ln))
            elif cmd == "show ip interface brief":
                body = ("Interface   IP-Address  OK? Method Status                Protocol\r\n"
                        "Gi0/1       10.10.0.1   YES NVRAM  up                    up\r\n"
                        "Gi0/2       unassigned  YES unset  down                  down")
            elif cmd == "":
                body = ""
            else:
                body = "        ^\r\n% Invalid input detected at '^' marker."
            chan.send(cmd + "\r\n" + (body + "\r\n" if body else "") + prompt)


@pytest.fixture
def fake_ios():  # noqa: ANN201
    key = paramiko.RSAKey.generate(2048)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    log: list[str] = []
    stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            try:
                srv.settimeout(0.5)
                client, _ = srv.accept()
            except TimeoutError:
                continue
            t = paramiko.Transport(client)
            t.add_server_key(key)
            ios = _IOS()
            t.start_server(server=ios)
            chan = t.accept(10)
            if chan is None:
                continue
            ios.shell.wait(5)
            try:
                _serve_cli(chan, log)
            except (OSError, EOFError):
                pass
            finally:
                t.close()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    yield port, log, key.get_fingerprint().hex()
    stop.set()
    srv.close()


def _cred(pw: str = "Cisco#123") -> Credential:
    return Credential(cred_id="dev", username="admin", kind="password", password=Secret(pw))


def test_real_ssh_session_against_fake_ios(fake_ios) -> None:  # noqa: ANN001
    port, log, _ = fake_ios
    approvals: list[tuple[str, str, str]] = []

    def approve(host: str, key_type: str, fp: str) -> bool:
        approvals.append((host, key_type, fp))
        return True

    conn = NetdevConnection(NetdevTarget("127.0.0.1", port, _cred()), approve_host_key=approve)
    with conn:
        assert approvals and approvals[0][1].startswith("ssh-")       # 호스트키 승인 콜백을 탔다
        assert conn.os == "cisco-ios" and "terminal length 0" in log  # 벤더 판별 → 그 벤더 페이징 해제만
        assert "set cli screen-length 0" not in log                    # 엉뚱한 벤더 명령을 던지지 않는다
        env = conn.probe()
        assert env.os == "cisco-ios" and env.os_version == "15.0(2)SE11" and env.hostname == "FAKE-R1"

        r = conn.exec(["show running-config"], timeout=10)
        assert r.ok and "hostname FAKE-R1" in r.stdout and "--More--" not in r.stdout and "FAKE-R1>" not in r.stdout
        conn.exec(["show running-config"], timeout=10)
        assert log.count("show running-config") == 1                  # 캐시
        bad = conn.exec(["configure terminal"], timeout=10)
        assert not bad.ok and "Invalid" in bad.stderr

        pack = loader.load(PACK)
        rules = pack.profiles["cisco-native"].native
        findings, errors = run_native(conn, env, rules)
    assert not errors, errors
    v = {f.rule_id: f.verdict_raw for f in findings}
    assert len(v) == 38
    assert v["N-03"] == "GOOD" and v["N-10"] == "GOOD" and v["N-15"] == "GOOD" and v["N-32"] == "GOOD"
    assert v["N-07"] == "VULN" and v["N-08"] == "VULN" and v["N-18"] == "VULN" and v["N-20"] == "VULN"
    assert v["N-24"] == "VULN" and v["N-06"] == "VULN" and v["N-09"] == "GOOD"
    assert log.count("show running-config") == 1                       # 38룰이 설정을 한 번만 받았다


def test_wrong_password_is_transport_error(fake_ios) -> None:  # noqa: ANN001
    port, _, _ = fake_ios
    conn = NetdevConnection(NetdevTarget("127.0.0.1", port, _cred("wrong")), approve_host_key=lambda *a: True)
    with pytest.raises(paramiko.AuthenticationException):
        conn.connect()


def test_host_key_rejected_means_no_session(fake_ios) -> None:  # noqa: ANN001
    port, log, _ = fake_ios
    conn = NetdevConnection(NetdevTarget("127.0.0.1", port, _cred()), approve_host_key=lambda *a: False)
    with pytest.raises((paramiko.SSHException, TransportError)):   # 정책이 HostKeyRejected(TransportError) 를 던진다
        conn.connect()
    assert "show version" not in log                                   # 거부되면 명령이 한 줄도 안 나간다
    assert isinstance(RemoteEnvironment(), RemoteEnvironment)
