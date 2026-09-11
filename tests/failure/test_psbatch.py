"""PowerShell 배치 — 스크립트 조립·파싱, 네이티브 실패 코드 보존, 캐시 소비, 배치 실패 시 개별 실행 폴백."""

from __future__ import annotations

import sys

import pytest

from infraguard.core.models import RemoteEnvironment
from infraguard.transport import psbatch
from infraguard.transport.base import ExecResult
from infraguard.transport.local import LocalConnection


def test_parse_roundtrip_markers_and_rc() -> None:
    cmds = ["Get-A", "Get-B", "Get-C"]
    text = ("junk\r\n@@IG_BEGIN 0@@\r\nline1\r\nline2\r\n@@IG_END 0 rc=0@@\r\n"
            "@@IG_BEGIN 1@@\r\n\r\n@@IG_END 1 rc=1@@\r\n@@IG_BEGIN 2@@\r\nbroken")
    got = psbatch.parse_output(text, cmds)
    assert got["Get-A"] == ("line1\r\nline2", 0)
    assert got["Get-B"][1] == 1 and got["Get-B"][0].strip() == ""
    assert "Get-C" not in got                       # 마커 깨진 블록은 빠진다 → 개별 실행 폴백


def test_script_resets_lastexitcode_per_command() -> None:
    s = psbatch.build_script(["icacls x", "Get-Y"])
    assert s.count("$global:LASTEXITCODE = 0") == 2 and "@@IG_END 0 rc=$__rc@@" in s


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="실제 PowerShell 필요")
def test_local_batch_keeps_native_failure_and_matches_single_exec() -> None:
    c = LocalConnection()
    cmds = ["Write-Output 'hello'", "cmd /c exit 3", "Get-ItemProperty -LiteralPath 'HKLM:\\NoSuchKey' -ErrorAction Stop",
            "$x = 1..3 | ForEach-Object { $_ * 2 }; $x -join ','"]
    c.prefetch_powershell(cmds)
    assert set(c._prefetched) == set(cmds)
    r = c.exec(["powershell", "-Command", cmds[0]], timeout=30)
    assert r.ok and r.stdout.strip() == "hello"
    r = c.exec(["powershell", "-Command", cmds[1]], timeout=30)
    assert not r.ok                                   # 네이티브 exit 3 이 rc=1 로 보존
    r = c.exec(["powershell", "-Command", cmds[2]], timeout=30)
    assert not r.ok and r.stdout.strip()              # 종료 예외 → 메시지가 stdout 에, rc=1
    r = c.exec(["powershell", "-Command", cmds[3]], timeout=30)
    assert r.ok and r.stdout.strip() == "2,4,6"
    assert not c._prefetched                          # 캐시는 한 번 쓰면 소비된다
    single = c.exec(["powershell", "-Command", cmds[3]], timeout=30)   # 캐시 없으면 개별 실행
    assert single.ok and single.stdout.strip() == "2,4,6"


def test_runner_falls_back_when_prefetch_raises(monkeypatch) -> None:  # noqa: ANN001
    from infraguard.orchestrator.native_runner import run_native  # noqa: PLC0415
    from infraguard.rules import NativeOutcome, NativeRule, load_all  # noqa: PLC0415

    calls: list[str] = []

    class Conn:
        def prefetch_powershell(self, cmds):  # noqa: ANN001,ANN202
            calls.append("prefetch")
            raise RuntimeError("winrm down")
        def exec(self, argv, **kw):  # noqa: ANN001,ANN003,ANN202
            calls.append("exec")
            return ExecResult(list(argv), 0, "ok", "", 1)

    reg = load_all()
    monkeypatch.setitem(reg, "T-01", NativeRule("T-01", "t", "상", ("windows",),
                                                lambda conn, env: NativeOutcome("GOOD", conn.exec(["powershell", "-Command", "x"]).stdout),
                                                collects=(("powershell", "x"),)))
    findings, errors = run_native(Conn(), RemoteEnvironment(os="windows"), ["T-01"])
    assert calls == ["prefetch", "exec"] and not errors and findings[0].verdict_raw == "GOOD"
