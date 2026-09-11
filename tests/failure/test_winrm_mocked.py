"""WinRM 전송 — 실서버 없이 pywinrm Session 을 모킹해 연결 실패·exec 디코딩·probe 파싱·W 룰 실행 경로를 태운다."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from infraguard.credentials.secret import Secret
from infraguard.credentials.session import Credential
from infraguard.orchestrator.native_runner import run_native
from infraguard.rulepack import loader
from infraguard.rules.declarative import evaluate, load_file
from infraguard.transport.base import TransportError
from infraguard.transport.winrm import WinRMConnection, WinRMTarget

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


class _Session:
    """winrm.Session 대역. run_ps(script) 의 script 에 든 키워드로 canned 출력."""

    def __init__(self, url: str, auth: tuple, **kw) -> None:  # noqa: ANN003
        self.url, self.auth, self.kw = url, auth, kw
        self.scripts: list[str] = []

    def run_ps(self, script: str) -> SimpleNamespace:
        self.scripts.append(script)
        table = {
            "PSVersion": ("5\r\n", 0),
            "Win32_OperatingSystem": ("Microsoft Windows Server 2022 Standard|10.0.20348|64비트|SRV01|svc_audit\r\n", 0),
            "-501": ("True\r\n", 0),
            "net accounts": ("잠금 임계값:                                          Never\r\n".encode("cp949").decode("cp949") + "", 0),
            "Netlogon": ("RequireSignOrSeal=1\r\nSealSecureChannel=1\r\nSignSecureChannel=1\r\n", 0),
            "AutoAdminLogon": ("1\r\n", 0),
        }
        for k, (out, rc) in table.items():
            if k in script:
                return SimpleNamespace(std_out=out.encode("utf-8"), std_err=b"", status_code=rc)
        return SimpleNamespace(std_out=b"", std_err=b"cmdlet not found", status_code=1)

    def run_cmd(self, cmd: str, args: list[str]) -> SimpleNamespace:
        return SimpleNamespace(std_out=b"ok\r\n", std_err=b"", status_code=0)


@pytest.fixture
def winrm_mock(monkeypatch):  # noqa: ANN001,ANN201
    made: list[_Session] = []
    def factory(url, auth, **kw):  # noqa: ANN001,ANN003,ANN202
        s = _Session(url, auth, **kw)
        made.append(s)
        return s
    monkeypatch.setitem(__import__("sys").modules, "winrm", SimpleNamespace(Session=factory))
    return made


def _cred() -> Credential:
    return Credential(cred_id="w", username="svc_audit", kind="password", password=Secret("P@ss"))


def test_connect_builds_ntlm_url_and_reveals_only_in_transport(winrm_mock) -> None:  # noqa: ANN001
    conn = WinRMConnection(WinRMTarget("10.0.0.7", 5985, _cred()))
    conn.connect()
    s = winrm_mock[0]
    assert s.url == "http://10.0.0.7:5985/wsman" and s.auth == ("svc_audit", "P@ss")
    assert s.kw["transport"] == "ntlm" and s.kw["server_cert_validation"] == "ignore"
    ssl = WinRMConnection(WinRMTarget("10.0.0.7", 5986, _cred(), use_ssl=True, verify_cert=True))
    ssl.connect()
    assert winrm_mock[1].url.startswith("https://") and winrm_mock[1].kw["server_cert_validation"] == "validate"


def test_key_auth_rejected() -> None:
    cred = Credential(cred_id="w", username="u", kind="key", key_path="C:/k")
    with pytest.raises(TransportError):
        WinRMConnection(WinRMTarget("h", credential=cred)).connect()


def test_probe_and_exec_decode(winrm_mock) -> None:  # noqa: ANN001
    conn = WinRMConnection(WinRMTarget("10.0.0.7", credential=_cred()))
    conn.connect()
    env = conn.probe()
    assert env.os == "windows" and "Server 2022" in env.os_version and env.hostname == "SRV01" and env.user == "svc_audit"
    r = conn.exec(["powershell", "-NoProfile", "-Command", "Get-ItemProperty Netlogon"], timeout=30)
    assert r.ok and r.stdout.startswith("RequireSignOrSeal=1")
    assert winrm_mock[0].scripts[-1].startswith("$ProgressPreference")   # 진행바 억제 프렐류드
    bad = conn.exec(["powershell", "-Command", "Get-Nothing"], timeout=30)
    assert not bad.ok and "cmdlet not found" in bad.stderr
    with pytest.raises(TransportError):
        conn.upload(Path("x"), "C:/x")


def test_windows_rules_end_to_end_over_mock(winrm_mock) -> None:  # noqa: ANN001
    conn = WinRMConnection(WinRMTarget("10.0.0.7", credential=_cred()))
    conn.connect()
    env = conn.probe()
    assert evaluate(load_file(PACK / "rules" / "W-02.yaml"), conn, env).verdict_raw == "VULN"   # Guest 활성
    assert evaluate(load_file(PACK / "rules" / "W-04.yaml"), conn, env).verdict_raw == "VULN"   # 잠금 임계값 Never(한글 라벨)
    assert evaluate(load_file(PACK / "rules" / "W-60.yaml"), conn, env).verdict_raw == "GOOD"
    assert evaluate(load_file(PACK / "rules" / "W-52.yaml"), conn, env).verdict_raw == "VULN"   # AutoAdminLogon=1
    pack = loader.load(PACK)
    findings, errors = run_native(conn, env, pack.profiles["windows-native"].native)
    assert not errors and len(findings) == 64                          # 응답 없는 cmdlet 도 예외 없이 판정 어휘로
    assert {f.verdict_raw for f in findings} <= {"GOOD", "VULN", "MANUAL", "NA"}
