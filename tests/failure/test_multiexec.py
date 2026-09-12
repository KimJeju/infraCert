"""멀티실행 — 정책 게이트(UI·워커 양쪽), 라이브러리 로드/등록 거부, 페이지 실행 흐름(가짜 연결)."""

from __future__ import annotations

import os
from pathlib import Path

from infraguard.assets.models import Host
from infraguard.orchestrator import multiexec as mx
from infraguard.transport.base import CleanupReport, Connection, ExecResult

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Fake(Connection):
    def __init__(self, host):  # noqa: ANN001
        self.host = host
    def connect(self): ...
    def probe(self): ...
    def exec(self, argv, **kw):
        return ExecResult(argv, 0, f"{self.host.label}: Linux 5.14 x86_64\n", "", 3)
    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def _hosts() -> list[Host]:
    return [Host(host_id="a", name="WEB-01", address="10.0.0.1"), Host(host_id="b", name="WEB-02", address="10.0.0.2"),
            Host(host_id="w", name="AD01", address="10.0.0.9", platform="windows"),
            Host(host_id="n", name="SW01", address="10.0.0.254", platform="network")]


def test_plan_requires_readonly_command_per_shell() -> None:
    hs = _hosts()
    p = mx.plan(hs, {"sh": "uname -a", "powershell": "Get-Date", "raw": "show version"})
    assert p.read_only and "대상 4대" in p.summary() and "예상 변경: 없음" in p.summary()
    p2 = mx.plan(hs[:2], {"sh": "rm -rf /tmp/x"})
    assert not p2.read_only and "거부 명령: rm" in p2.violations["sh"][0]
    p3 = mx.plan(hs, {"sh": "uname -a"})            # windows/network 용 명령이 비어 있음
    assert not p3.read_only and "powershell" in p3.violations and "raw" in p3.violations


def test_run_one_blocks_write_before_connecting(monkeypatch) -> None:  # noqa: ANN001
    called = {"n": 0}

    def bc(*a, **k):  # noqa: ANN002,ANN003,ANN202
        called["n"] += 1
        return _Fake(a[0])

    monkeypatch.setattr("infraguard.ui.workers.build_connection", bc)
    h = _hosts()[0]
    bad = mx.run_one(h, None, "systemctl restart sshd", lambda *a: True)
    assert "정책 위반" in bad.error and called["n"] == 0
    ok = mx.run_one(h, None, "uname -a", lambda *a: True)
    assert ok.ok and ok.first_line().startswith("WEB-01: Linux") and called["n"] == 1


def test_library_loads_builtin_and_filters_user_write_entries() -> None:
    lib = mx.load_library()
    names = {e.name for e in lib}
    assert {"OS 확인", "리스닝 포트 (ss/netstat)", "sshd_config"} <= names
    assert all(not e.user for e in lib)
    user = {"Custom": [{"name": "위험", "sh": "rm -rf /"}, {"name": "안전", "sh": "id"}]}
    lib2 = mx.load_library(user)
    assert [e.name for e in lib2 if e.user] == ["안전"]
    assert mx.validate_entry({"sh": "chmod 777 /etc/passwd"}) and not mx.validate_entry({"sh": "ls -l /etc"})
    assert mx.validate_entry({}) == ["명령이 비어 있음"]


def test_audit_masks_and_render(tmp_path: Path) -> None:
    r = mx.ExecOutcome(host_id="a", label="WEB-01", shell="sh", cmd="cat x", exit_code=0,
                       stdout="password=Secret123!\nok\n", duration_ms=5)
    p = mx.write_audit(tmp_path, {"sh": "cat x"}, [r])
    txt = p.read_text(encoding="utf-8")
    assert "Secret123!" not in txt and "WEB-01" in txt and "cat x" in txt
    assert "===== WEB-01 (rc=0, 5ms)" in mx.render_text({"sh": "cat x"}, [r])


def test_page_runs_checked_hosts_with_confirmation(qtbot, tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from PySide6.QtWidgets import QMessageBox
    from infraguard.ui.pages.multiexec import MultiExecPage
    monkeypatch.setattr("infraguard.ui.workers.build_connection", lambda h, c, a, ch=None, **k: _Fake(h))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    page = MultiExecPage(lambda h: object(), lambda *a: True, lambda *a: False, tmp_path / "logs")
    qtbot.addWidget(page)
    page.set_hosts(_hosts()[:2])
    page._check_all(True)
    page.cmd["sh"].setText("uname -a")
    page._run()
    qtbot.waitUntil(lambda: page.table.rowCount() == 2, timeout=10000)
    assert page.export_btn.isEnabled() and "완료 2대" in page.status.text()
    assert list((tmp_path / "logs").glob("multiexec_*.log"))
    # 쓰기 명령은 확인창 전에 막힌다
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warned.append(a[1])))
    page.cmd["sh"].setText("rm -rf /tmp/x")
    page._run()
    assert warned and "읽기 전용" in warned[0]
