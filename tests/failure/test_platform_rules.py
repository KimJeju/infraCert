"""플랫폼 확장 — Windows(PowerShell)/Oracle(sqlplus)/Cisco(show) 선언형 룰과 전송 계층.

실기기 없이: 가짜 Connection 에 canned 출력을 물려 판정 경로를 검증한다. 로컬 PowerShell 은 이 PC 가 Windows 일 때 실제 실행.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from infraguard.assets.models import Host
from infraguard.core.models import Platform, RemoteEnvironment
from infraguard.credentials.secret import Secret
from infraguard.credentials.session import Credential
from infraguard.rules.declarative import build_argv, evaluate, load_file
from infraguard.transport import netdev
from infraguard.transport.base import CleanupReport, Connection, ExecResult
from infraguard.transport.local import LocalConnection
from infraguard.transport.ssh import SSHConnection
from infraguard.transport.winrm import WinRMConnection
from infraguard.ui.workers import build_connection

RULES = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026" / "rules"


class Fake(Connection):
    """argv 마지막 요소(명령)를 키로 canned 출력을 돌려준다. 없는 명령은 exit 1."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def connect(self) -> None: ...
    def probe(self) -> RemoteEnvironment: return RemoteEnvironment()
    def exec(self, argv, *, timeout, cwd=None, stdin_data=None, max_output=1 << 20):  # noqa: ANN001,ANN201
        self.calls.append(list(argv))
        cmd = argv[-1]
        for k, v in self.answers.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        return ExecResult(argv, 1, "", "no such command", 1)
    def upload(self, local, remote): ...  # noqa: ANN001
    def download(self, remote, local): ...  # noqa: ANN001
    def cleanup(self, paths): return CleanupReport()  # noqa: ANN001
    def close(self) -> None: ...


def _rule(rid: str):  # noqa: ANN202
    return load_file(RULES / f"{rid}.yaml")


# ------------------------------------------------------------------ Cisco
CISCO_BAD = """!
hostname R1
enable password cisco
service tcp-small-servers
ip http server
snmp-server community public RW
line vty 0 4
 exec-timeout 0 0
 transport input telnet
!
"""
CISCO_GOOD = """!
service password-encryption
service timestamps log datetime msec
service tcp-keepalives-in
no service pad
enable secret 5 $1$abc
no ip source-route
no ip bootp server
no cdp run
no ip domain-lookup
no ip http server
no ip http secure-server
logging buffered 64000
logging host 10.0.0.5
ntp server 10.0.0.9
banner login ^C Authorized only ^C
snmp-server community Xk9#pq2!v RO 10
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 transport input ssh
line aux 0
 no exec
 transport input none
!
"""


@pytest.mark.parametrize("rid,bad,good", [
    ("N-01", "MANUAL", "GOOD"), ("N-03", "VULN", "GOOD"), ("N-06", "VULN", "GOOD"), ("N-07", "VULN", "GOOD"),
    ("N-08", "VULN", "GOOD"), ("N-09", "MANUAL", "GOOD"), ("N-10", "VULN", "GOOD"), ("N-11", "VULN", "GOOD"),
    ("N-15", "VULN", "GOOD"), ("N-16", "VULN", "GOOD"), ("N-18", "VULN", "GOOD"), ("N-19", "VULN", "GOOD"),
    ("N-20", "VULN", "GOOD"), ("N-25", "VULN", "GOOD"), ("N-27", "VULN", "GOOD"), ("N-28", "VULN", "GOOD"),
    ("N-29", "VULN", "GOOD"), ("N-30", "VULN", "GOOD"), ("N-32", "VULN", "GOOD"), ("N-36", "VULN", "GOOD"),
    ("N-37", "VULN", "GOOD"),
])
def test_cisco_rules_bad_vs_good(rid: str, bad: str, good: str) -> None:
    spec = _rule(rid)
    assert spec.shell == "raw" and spec.platforms == ["cisco-ios"]
    env = RemoteEnvironment(os="cisco-ios")
    assert evaluate(spec, Fake({"show running-config": CISCO_BAD}), env).verdict_raw == bad
    assert evaluate(spec, Fake({"show running-config": CISCO_GOOD}), env).verdict_raw == good


def test_cisco_raw_argv_is_single_command() -> None:
    spec = _rule("N-06")
    assert build_argv(spec, "show running-config", {}) == ["show running-config"]


def test_netdev_prompt_and_echo_strip() -> None:
    assert netdev._ends_with_prompt("banner\r\nRouter#")
    assert netdev._ends_with_prompt("x\nuser@host> ")
    assert netdev._ends_with_prompt("R1(config)#")
    assert not netdev._ends_with_prompt("Building configuration...\n")
    assert not netdev._ends_with_prompt("hostname R1\n!")
    out = netdev._strip_echo("show running-config\r\n!\r\nhostname R1\r\n!\r\nR1#", "show running-config")
    assert out == "!\nhostname R1\n!"


class _Chan:
    """가짜 invoke_shell 채널: 보낸 명령에 따라 응답 + 프롬프트."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self._out = b"Welcome\r\nR1>"

    def send(self, s: str) -> None:
        self.sent.append(s)
        cmd = s.strip()
        body = {"show version": "Cisco IOS Software, C2960 Software, Version 15.0(2)SE",
                "terminal length 0": "", "show running-config": CISCO_GOOD}.get(cmd, "% Invalid input detected at '^' marker.")
        self._out = (cmd + "\r\n" + body.replace("\n", "\r\n") + "\r\nR1>").encode()

    def recv(self, n: int) -> bytes:
        o, self._out = self._out, b""
        return o

    def close(self) -> None: ...


def test_netdev_session_vendor_paging_cache_and_invalid() -> None:
    c = netdev.NetdevConnection(netdev.NetdevTarget("10.0.0.1"))
    c._chan = _Chan()
    c._init_session()
    assert c.os == "cisco-ios" and "terminal length 0\n" in c._chan.sent
    env = c.probe()
    assert env.os == "cisco-ios" and env.os_version == "15.0(2)SE"
    r1 = c.exec(["show running-config"], timeout=5)
    r2 = c.exec(["show running-config"], timeout=5)
    assert r1.ok and "enable secret" in r1.stdout and r2.stdout == r1.stdout
    assert c._chan.sent.count("show running-config\n") == 1          # 캐시 — 두 번 안 보낸다
    bad = c.exec(["configure terminal"], timeout=5)
    assert not bad.ok and "Invalid" in bad.stderr


# ------------------------------------------------------------------ Oracle
def test_oracle_rules_with_canned_sqlplus() -> None:
    env = RemoteEnvironment(os="linux", params={"ORACLE_HOME": "/u01/app/oracle", "ORACLE_SID": "ORCL"})
    assert evaluate(_rule("D-02"), Fake({"dba_users": "SCOTT:OPEN\n"}), env).verdict_raw == "VULN"
    assert evaluate(_rule("D-02"), Fake({"dba_users": ""}), env).verdict_raw == "GOOD"
    assert evaluate(_rule("D-02"), Fake({"dba_users": "ORA-01017: invalid username/password\n"}), env).verdict_raw == "MANUAL"
    assert evaluate(_rule("D-19"), Fake({"v$parameter": "os_roles=FALSE\nremote_os_authent=FALSE\nremote_os_roles=FALSE\n"}), env).verdict_raw == "GOOD"
    assert evaluate(_rule("D-19"), Fake({"v$parameter": "os_roles=FALSE\nremote_os_authent=TRUE\n"}), env).verdict_raw == "VULN"
    assert evaluate(_rule("D-09"), Fake({"FAILED_LOGIN_ATTEMPTS": "UNLIMITED\n"}), env).verdict_raw == "VULN"
    assert evaluate(_rule("D-09"), Fake({"FAILED_LOGIN_ATTEMPTS": "5\n"}), env).verdict_raw == "GOOD"
    assert evaluate(_rule("D-16"), Fake({}), env).verdict_raw == "NA"


def test_oracle_argv_gets_env_prefix_and_rejects_bad_params() -> None:
    spec = _rule("D-02")
    argv = build_argv(spec, spec.collect[0].cmd, {"ORACLE_HOME": "/u01/app/oracle", "ORACLE_SID": "ORCL"})
    assert argv[:3] == ["env", "ORACLE_HOME=/u01/app/oracle", "ORACLE_SID=ORCL"] and argv[3:5] == ["sh", "-c"]
    with pytest.raises(ValueError):
        build_argv(spec, spec.collect[0].cmd, {"ORACLE_HOME": "/x; rm -rf /"})


# ------------------------------------------------------------------ Windows
def test_windows_rules_with_canned_powershell() -> None:
    env = RemoteEnvironment(os="windows")
    assert evaluate(_rule("W-02"), Fake({"-501": "False\r\n"}), env).verdict_raw == "GOOD"
    assert evaluate(_rule("W-02"), Fake({"-501": "True\r\n"}), env).verdict_raw == "VULN"
    acc = "Lockout threshold:                                    3\r\nMinimum password length:                              8\r\n" \
          "Maximum password age (days):                          90\r\nMinimum password age (days):                          1\r\n"
    assert evaluate(_rule("W-04"), Fake({"net accounts": acc}), env).verdict_raw == "GOOD"
    assert evaluate(_rule("W-09"), Fake({"net accounts": acc}), env).verdict_raw == "GOOD"
    ko = "잠금 임계값:                                          Never\r\n"
    assert evaluate(_rule("W-04"), Fake({"net accounts": ko}), env).verdict_raw == "VULN"
    reg = "RequireSignOrSeal=1\r\nSealSecureChannel=1\r\nSignSecureChannel=1\r\n"
    assert evaluate(_rule("W-60"), Fake({"Netlogon": reg}), env).verdict_raw == "GOOD"   # \r 이 값에 붙지 않는다
    spec = _rule("W-60")
    assert build_argv(spec, "x", {})[:2] == ["powershell", "-NoProfile"]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="로컬 PowerShell 은 Windows 에서만")
def test_local_powershell_runs_real_rule() -> None:
    conn = LocalConnection()
    env = conn.probe()
    assert env.os == "windows"
    out = evaluate(_rule("W-64"), conn, env)
    assert out.verdict_raw in ("GOOD", "VULN", "MANUAL") and "Enabled" in out.evidence


def test_build_connection_picks_transport_by_platform() -> None:
    cred = Credential(cred_id="c", username="u", kind="password", password=Secret("p"))
    def host(platform: str, port: int = 22) -> Host:
        return Host(host_id="h", name="h", address="10.0.0.1", port=port, platform=platform)
    w = build_connection(host(Platform.WINDOWS), cred, None)
    assert isinstance(w, WinRMConnection) and w.target.port == 5985 and not w.target.use_ssl
    w2 = build_connection(host(Platform.WINDOWS, 5986), cred, None)
    assert w2.target.use_ssl
    assert isinstance(build_connection(host(Platform.NETWORK), cred, None), netdev.NetdevConnection)
    assert isinstance(build_connection(host(Platform.LINUX), cred, None), SSHConnection)
