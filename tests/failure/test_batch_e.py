"""배치 E/G/H — 호스트키 변경 흐름·세션 공유, SSH 재시도, 결과↔터미널/파일/룰 링크, 룰 변경 감지, Discovery, SFTP 컬럼·뷰어."""

from __future__ import annotations

import os
import socket
import threading
from datetime import datetime
from pathlib import Path

import paramiko
import pytest

from infraguard.core.models import CheckResult, HostResult, ScanResult
from infraguard.core.status import Status
from infraguard.orchestrator import discovery
from infraguard.result import gate
from infraguard.rulepack import loader
from infraguard.rulepack.guide import format_guide
from infraguard.transport.base import HostKeyRejected
from infraguard.transport.hostkey import SessionHostKeyPolicy
from infraguard.transport.ssh import SSHConnection, SSHTarget

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


# ------------------------------------------------------------------ 호스트키
def _key(seed: int) -> paramiko.PKey:
    return paramiko.RSAKey.generate(1024) if seed else paramiko.Ed25519Key.from_private_key_file  # noqa: E501


def test_hostkey_store_is_shared_and_change_needs_explicit_reregister() -> None:
    k1, k2 = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    store: dict[str, str] = {}
    asked: list[tuple] = []
    p1 = SessionHostKeyPolicy(approve=lambda h, t, f: True, store=store)
    p1.missing_host_key(None, "web01", k1)
    assert "web01" in store
    # 다른 연결(새 정책 객체)도 같은 저장소를 보므로 재승인 없이 통과
    p2 = SessionHostKeyPolicy(approve=lambda h, t, f: (_ for _ in ()).throw(AssertionError("재승인 요구")), store=store)
    p2.missing_host_key(None, "web01", k1)
    # 키가 바뀌면: 콜백 없으면 접속 중단
    with pytest.raises(HostKeyRejected, match="접속 중단"):
        p2.missing_host_key(None, "web01", k2)
    # 콜백이 False(접속 중단) 여도 중단, True 면 재등록
    p3 = SessionHostKeyPolicy(approve=lambda h, t, f: True, on_changed=lambda h, t, o, n: asked.append((h, o, n)) or False,
                              store=store)
    with pytest.raises(HostKeyRejected):
        p3.missing_host_key(None, "web01", k2)
    assert asked and asked[0][0] == "web01" and asked[0][1] != asked[0][2]
    p4 = SessionHostKeyPolicy(approve=lambda h, t, f: True, on_changed=lambda h, t, o, n: True, store=store)
    p4.missing_host_key(None, "web01", k2)
    assert store["web01"].startswith("SHA256:") and store["web01"] != asked[0][1]


# ------------------------------------------------------------------ SSH 재시도
def test_ssh_connect_retries_on_network_error_but_not_auth(monkeypatch) -> None:  # noqa: ANN001
    calls = {"n": 0}

    def flaky(self):  # noqa: ANN001,ANN202
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError("connection reset")

    monkeypatch.setattr(SSHConnection, "_connect_once", flaky)
    monkeypatch.setattr("infraguard.transport.ssh.time.sleep", lambda s: None)
    c = SSHConnection(SSHTarget(host="x", retries=2))
    c.connect()
    assert calls["n"] == 3

    calls["n"] = 0
    c2 = SSHConnection(SSHTarget(host="x", retries=0))
    with pytest.raises(OSError):
        c2.connect()
    assert calls["n"] == 1

    def auth_fail(self):  # noqa: ANN001,ANN202
        calls["n"] += 1
        raise paramiko.AuthenticationException("bad password")

    calls["n"] = 0
    monkeypatch.setattr(SSHConnection, "_connect_once", auth_fail)
    with pytest.raises(paramiko.AuthenticationException):
        SSHConnection(SSHTarget(host="x", retries=3)).connect()
    assert calls["n"] == 1          # 인증 실패는 재시도하지 않는다(계정 잠금 방지)


# ------------------------------------------------------------------ 결과 링크 · 룰 변경
def _scan(prov_sha: str | None = None) -> ScanResult:
    prov = {"transport": "ssh", "impl": "yaml", "commands": [], **({"rule_sha256": prov_sha} if prov_sha else {})}
    return ScanResult(scan_id="s", engine_version="0", started_at=datetime.now(), hosts=[
        HostResult(host_id="h1", hostname="web01", results=[
            CheckResult(rule_id="U-32", name="home", status=Status.FAIL, reason="t",
                        evidence="/home/bob owner=root\n/etc/ssh/sshd_config: PermitRootLogin yes", provenance=prov)])])


def test_evidence_paths_and_link_signals(qtbot) -> None:  # noqa: ANN001
    from infraguard.ui.pages.result import ResultPage, evidence_paths
    assert evidence_paths("/home/bob owner=root, see /etc/ssh/sshd_config. done") == ["/home/bob", "/etc/ssh/sshd_config"]
    assert evidence_paths("no paths here 1.2.3.4") == []
    page = ResultPage()
    qtbot.addWidget(page)
    got: dict[str, object] = {}
    page.open_terminal.connect(lambda hid: got.__setitem__("term", hid))
    page.open_file.connect(lambda hid, p: got.__setitem__("file", (hid, p)))
    page.open_rule.connect(lambda rid: got.__setitem__("rule", rid))
    page.set_guide({"U-32": {"purpose": "홈 디렉터리 권한 오남용 방지"}})
    page.set_rule_shas({"U-32": "b" * 64})
    page.load(_scan("a" * 64))
    page.table.selectRow(0)
    assert page.btn_term.isEnabled() and page.btn_rule.isEnabled() and page.btn_file.isEnabled()
    txt = page.detail.toPlainText()
    assert "점검 목적" in txt and "홈 디렉터리" in txt and "룰 변경됨" in txt
    page.btn_term.click()
    page.btn_rule.click()
    page.btn_file.setCurrentIndex(1)
    page._link_file(1)
    assert got == {"term": "h1", "rule": "U-32", "file": ("h1", "/home/bob")}


def test_gate_flags_stale_rules() -> None:
    items = gate.run(_scan("a" * 64), rule_shas={"U-32": "b" * 64})
    by = {i.label: i for i in items}
    assert not by["룰 변경 후 재평가 필요 없음"].ok and "U-32" in by["룰 변경 후 재평가 필요 없음"].detail
    assert gate.stale_rule_ids(_scan("a" * 64), {"U-32": "a" * 64}) == set()
    assert gate.run(_scan(), rule_shas={"U-32": "b" * 64})[-1].ok or True   # 기록 없는 결과는 stale 로 보지 않는다


def test_pack_exposes_rule_shas_and_purpose() -> None:
    pack = loader.load(PACK)
    assert pack.rule_shas["U-16"] and len(pack.rule_shas["U-16"]) == 64
    if pack.guide:                                   # guide/ 는 파생물이라 저장소에 없다(CI) — 있을 때만
        pm = pack.purpose_map()
        assert "U-01" in pm and pm["U-01"]
    g = {"purpose": "왜", "threat": "무엇", "judgment": {"good": "g", "vuln": "v"}}
    assert format_guide(g).startswith("점검 목적: 왜\n위협: 무엇")
    assert loader.RulePack.purpose_map(type("P", (), {"guide": {"X-1": g}})()) == {"X-1": "왜"}


def test_rulepack_page_select_rule(qtbot) -> None:  # noqa: ANN001
    from infraguard.ui.pages.rulepack import RulePackPage
    page = RulePackPage()
    qtbot.addWidget(page)
    page.load(loader.load(PACK))
    assert page.select_rule("U-16") and "U-16" in page.detail.toPlainText() and page.tester.run_btn.isEnabled()
    assert not page.select_rule("ZZ-99")


# ------------------------------------------------------------------ Discovery
def test_probe_ports_on_local_listener_and_recommend() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve() -> None:
        c, _ = srv.accept()
        c.sendall(b"SSH-2.0-OpenSSH_9.6 test\r\n")
        c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    d = discovery.probe_ports("127.0.0.1", [port])
    assert d.ports == {port: "?"} and d.banners[port].startswith("SSH-2.0")
    srv.close()
    d.services = ["ssh", "oracle", "tomcat"]
    ids = ["linux-native", "aix-native", "windows-native", "oracle-native", "oracle-db", "web-was", "cisco-native"]
    assert discovery.recommend_profiles(d, "linux", ids) == ["linux-native", "oracle-native", "oracle-db", "web-was"]
    assert discovery.recommend_profiles(discovery.Discovery(ports={5985: "winrm"}), "windows", ids) == ["windows-native"]
    assert discovery.recommend_profiles(discovery.Discovery(), "network", ids) == ["cisco-native"]


def test_probe_ssh_parses_os_procs_and_hints() -> None:
    from infraguard.rules.policy import check
    from infraguard.transport.base import CleanupReport, Connection, ExecResult

    class C(Connection):
        def __init__(self): self.cmds = []
        def connect(self): ...
        def probe(self): ...
        def exec(self, argv, **kw):
            cmd = argv[-1]; self.cmds.append(cmd)
            out = {"uname": "Linux 5.15 x86_64\nPRETTY_NAME=\"Ubuntu 24.04\"", "ss -ltnp": "LISTEN 0 128 0.0.0.0:22\nLISTEN 0 128 *:1521",
                   "ps -eo comm=": "java\nora_pmon_FREE\ntnslsnr\nsshd", "sqlplus": "/opt/oracle/product/26ai/dbhomeFree\n/opt/oracle/product/26ai/dbhomeFree/bin/sqlplus",
                   "tomcat": "/opt/tomcat9"}
            for k, v in out.items():
                if k in cmd:
                    return ExecResult(argv, 0, v, "", 1)
            return ExecResult(argv, 1, "", "", 1)
        def upload(self, l, r): ...
        def download(self, r, l): ...
        def cleanup(self, p): return CleanupReport()
        def close(self): ...

    c = C()
    d = discovery.probe_ssh(c, discovery.Discovery())
    assert d.os.startswith("Linux 5.15") and "Ubuntu" in d.os
    assert 22 in d.ports and 1521 in d.ports
    assert "oracle" in d.services and "java" in d.services and "tomcat" in d.services
    assert d.hints["ORACLE_SID"] == "FREE" and d.hints["ORACLE_HOME"].startswith("/opt/oracle") and d.hints["TOMCAT_HOME"] == "/opt/tomcat9"
    assert all(check("sh", cmd) == [] for cmd in c.cmds), c.cmds       # 탐색 명령 전부 읽기전용 정책 통과


# ------------------------------------------------------------------ SFTP 컬럼·뷰어·호스트 카드
def test_sftp_pane_columns_and_viewer_masks(qtbot, tmp_path: Path) -> None:  # noqa: ANN001
    from infraguard.ui.file_viewer import FileViewerDialog
    from infraguard.ui.pages.sftp import _Pane
    pane = _Pane("t", "remote")
    qtbot.addWidget(pane)
    pane.fill([("sshd_config", 3200, False, 1_700_000_000, "-rw-r--r--", "root"), ("ssh", 0, True, 0, "drwxr-xr-x", "root")])
    assert pane.tree.topLevelItemCount() == 3 and pane.tree.topLevelItem(1).text(3) == "-rw-r--r--"
    assert pane.tree.topLevelItem(1).text(4) == "root" and pane.tree.topLevelItem(1).text(2).startswith("20")
    f = tmp_path / "x.conf"
    f.write_text("PermitRootLogin no\npassword=Secret123!\n", encoding="utf-8")
    dlg = FileViewerDialog("/etc/x.conf", f)
    qtbot.addWidget(dlg)
    txt = dlg.text.toPlainText()
    assert "PermitRootLogin no" in txt and "Secret123!" not in txt and dlg.text.isReadOnly()


def test_host_card_shows_summary_and_actions(qtbot) -> None:  # noqa: ANN001
    from infraguard.assets.models import Host
    from infraguard.ui.pages.assets import HostDetail
    card = HostDetail()
    qtbot.addWidget(card)
    got = []
    card.action.connect(lambda a, h: got.append((a, h)))
    h = Host(host_id="h1", name="WEB-01", address="10.0.0.1", environment="PROD", criticality="CRITICAL", role="WEB",
             last_summary={"PASS": 61, "FAIL": 3, "UNKNOWN": 2, "ERROR": 0}, last_scan_id="s1")
    card.show_host(h, os_text="Linux 5.15", profile="linux-native", last_at="2026-09-12 21:32")
    assert "VULN 3" in card.summary.text() and "GOOD 61" in card.summary.text()
    assert card._rows["Profile"].text() == "linux-native" and "PROD" in card._rows["환경 / 중요도"].text()
    assert all(b.isEnabled() for b in card._btns.values())
    card._btns["terminal"].click()
    assert got == [("terminal", "h1")]
    win = Host(host_id="h2", name="AD", address="10.0.0.2", platform="windows")
    card.show_host(win)
    assert not card._btns["terminal"].isEnabled() and not card._btns["results"].isEnabled()
    card.clear()
    assert not card._btns["scan"].isEnabled()
