"""Junos variant — N-xx 룰이 env.os=junos 면 set 문법 블록으로 판정되고, 가짜 Junos SSH 서버로 전송 경로까지 태운다."""

from __future__ import annotations

import re
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
from infraguard.rules.declarative import evaluate, load_file
from infraguard.transport.netdev import NetdevConnection, NetdevTarget
from tests.failure.test_platform_rules import Fake

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"
RULES = PACK / "rules"

JUNOS_BAD = """set system services telnet
set system services web-management http
set snmp community public authorization read-write
set protocols lldp interface all
set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24
"""
JUNOS_GOOD = """set system root-authentication encrypted-password "$6$abc"
set system login password minimum-length 10
set system login retry-options tries-before-disconnect 3
set system login class admin idle-timeout 5
set system login message "Authorized access only"
set system services ssh client-alive-interval 60
set system syslog host 10.0.0.5 any any
set system ntp server 10.0.0.9
set system no-redirects
set system ports auxiliary disable
set snmp community Xk9#pq2!v authorization read-only
set snmp community Xk9#pq2!v clients 10.0.0.0/24
set interfaces lo0 unit 0 family inet filter input protect-re
set interfaces ge-0/0/1 unit 0 family inet rpf-check
"""


@pytest.mark.parametrize("rid,bad,good", [
    ("N-01", "VULN", "GOOD"), ("N-02", "MANUAL", "GOOD"), ("N-04", "VULN", "GOOD"), ("N-06", "VULN", "GOOD"),
    ("N-07", "VULN", "GOOD"), ("N-08", "VULN", "GOOD"), ("N-09", "MANUAL", "GOOD"), ("N-10", "VULN", "GOOD"),
    ("N-11", "VULN", "GOOD"), ("N-15", "VULN", "GOOD"), ("N-18", "VULN", "GOOD"), ("N-19", "VULN", "GOOD"),
    ("N-20", "VULN", "GOOD"), ("N-22", "MANUAL", "GOOD"), ("N-25", "VULN", "GOOD"), ("N-27", "VULN", "GOOD"),
    ("N-30", "VULN", "GOOD"), ("N-34", "VULN", "GOOD"),
])
def test_junos_variant_bad_vs_good(rid: str, bad: str, good: str) -> None:
    spec = load_file(RULES / f"{rid}.yaml")
    assert "junos" in spec.all_platforms() and spec.for_platform("junos").shell == "raw"
    env = RemoteEnvironment(os="junos")
    assert evaluate(spec, Fake({"display set": JUNOS_BAD}), env).verdict_raw == bad
    assert evaluate(spec, Fake({"display set": JUNOS_GOOD}), env).verdict_raw == good


def test_same_rule_still_uses_cisco_block_for_ios() -> None:
    spec = load_file(RULES / "N-08.yaml")
    c = Fake({"show running-config": "line vty 0 4\n transport input ssh\n!"})
    assert evaluate(spec, c, RemoteEnvironment(os="cisco-ios")).verdict_raw == "GOOD"
    assert any("show running-config" == a[-1] for a in c.calls) and not any("display set" in a[-1] for a in c.calls)


# ------------------------------------------------------------------ 가짜 Junos SSH 서버
class _Srv(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.shell = threading.Event()
    def check_auth_password(self, u: str, p: str) -> int:
        return paramiko.AUTH_SUCCESSFUL if (u, p) == ("admin", "Juniper#1") else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u: str) -> str: return "password"
    def check_channel_request(self, kind: str, chanid: int) -> int: return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *a) -> bool: return True  # noqa: ANN002
    def check_channel_shell_request(self, ch) -> bool:  # noqa: ANN001
        self.shell.set()
        return True


def _cli(chan: paramiko.Channel, log: list[str]) -> None:
    prompt = "admin@FAKE-MX> "
    chan.send("--- JUNOS 21.4R3 Kernel 64-bit ---\r\n" + prompt)
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
                body = "Hostname: FAKE-MX\r\nModel: mx204\r\nJunos: 21.4R3.15\r\nJUNOS OS Kernel 64-bit"
            elif cmd == "set cli screen-length 0":
                body = "Screen length set to 0"
            elif cmd == "show configuration | display set":
                body = JUNOS_GOOD.replace("\n", "\r\n")
            elif cmd.startswith("show configuration | display set | match "):
                pat = cmd.split("match ", 1)[1].strip('"')
                body = "\r\n".join(ln for ln in JUNOS_GOOD.splitlines() if re.search(pat, ln))
            elif cmd == "show interfaces terse":
                body = "Interface  Admin Link Proto\r\nge-0/0/0   up    up   inet\r\nge-0/0/1   up    down"
            elif cmd == "":
                body = ""
            else:
                body = "                 ^\r\nsyntax error, expecting <command>."
            chan.send(cmd + "\r\n" + (body + "\r\n" if body else "") + prompt)


@pytest.fixture
def fake_junos():  # noqa: ANN201
    key = paramiko.RSAKey.generate(2048)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]; log: list[str] = []; stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            try:
                srv.settimeout(0.5); client, _ = srv.accept()
            except TimeoutError:
                continue
            t = paramiko.Transport(client); t.add_server_key(key); s = _Srv(); t.start_server(server=s)
            ch = t.accept(10)
            if ch is None:
                continue
            s.shell.wait(5)
            try:
                _cli(ch, log)
            except (OSError, EOFError):
                pass
            finally:
                t.close()
    threading.Thread(target=run, daemon=True).start()
    yield port, log
    stop.set(); srv.close()


def test_junos_over_real_ssh(fake_junos) -> None:  # noqa: ANN001
    port, log = fake_junos
    cred = Credential(cred_id="d", username="admin", kind="password", password=Secret("Juniper#1"))
    conn = NetdevConnection(NetdevTarget("127.0.0.1", port, cred), approve_host_key=lambda *a: True)
    with conn:
        assert conn.os == "junos" and "set cli screen-length 0" in log and "terminal length 0" not in log
        env = conn.probe()
        assert env.os == "junos" and env.os_version == "21.4R3.15" and env.hostname == "admin@FAKE-MX"
        pack = loader.load(PACK)
        findings, errors = run_native(conn, env, pack.profiles["junos-native"].native)
    assert not errors, errors
    v = {f.rule_id: f.verdict_raw for f in findings}
    assert len(v) == 38 and v["N-08"] == "GOOD" and v["N-18"] == "GOOD" and v["N-24"] == "VULN"
    assert log.count("show configuration | display set") == 1        # 캐시
