"""번들 인터프리터 폴백 — ksh 선언인데 대상에 없으면 sh 로 돌리고 사유를 남긴다. 실패 메시지엔 exit·stderr 가 보인다."""

from __future__ import annotations

from pathlib import Path

from infraguard.core.models import RemoteEnvironment
from infraguard.orchestrator import preflight
from infraguard.orchestrator.remote_runner import RemoteRunner, RunSpec
from infraguard.transport.base import CleanupReport, Connection, ExecResult


class _Rec(Connection):
    def __init__(self, outputs: dict[str, str] | None = None):
        self.cmds: list[str] = []
        self.outputs = outputs or {}

    def connect(self): ...
    def probe(self): return RemoteEnvironment(os="linux")
    def exec(self, argv, **kw):
        cmd = argv[-1]
        self.cmds.append(cmd)
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        return ExecResult(argv, 1 if "command -v" in cmd else 0, "" if "command -v" in cmd else "1\n", "", 1)
    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def test_launch_falls_back_to_sh_when_interpreter_missing(tmp_path: Path) -> None:
    (tmp_path / "s.sh").write_text("echo")
    conn = _Rec()
    spec = RunSpec(bundle_id="b", script=tmp_path / "s.sh", interpreter="ksh", env={"ORACLE_SID": "FREE"})
    RemoteRunner(conn)._launch(spec, "/tmp/ig")
    cmd = conn.cmds[-1]
    assert "command -v ksh" in cmd and "ORACLE_SID=FREE ksh /tmp/ig/s.sh" in cmd
    assert "falling back to sh" in cmd and "ORACLE_SID=FREE sh /tmp/ig/s.sh" in cmd
    assert cmd.count("'") % 2 == 0                      # nohup sh -c '…' 인용이 깨지지 않는다
    # sh 선언·미선언은 그대로
    RemoteRunner(conn)._launch(RunSpec(bundle_id="b", script=tmp_path / "s.sh", interpreter="sh"), "/tmp/ig")
    assert "command -v" not in conn.cmds[-1] and "sh /tmp/ig/s.sh" in conn.cmds[-1]
    RemoteRunner(conn)._launch(RunSpec(bundle_id="b", script=tmp_path / "s.sh"), "/tmp/ig")
    assert "command -v" not in conn.cmds[-1] and "/tmp/ig/s.sh" in conn.cmds[-1]


def test_preflight_notes_missing_interpreter() -> None:
    conn = _Rec({"date +%s": str(int(__import__("time").time()))})
    notes = preflight.run(conn, RemoteEnvironment(os="linux", privileged=True), native=[], has_bundles=True,
                          interpreters=["ksh", "sh", "ksh"])
    assert any("ksh 없음" in n for n in notes) and sum("없음" in n for n in notes) == 1
    ok = _Rec({"command -v ksh": "/bin/ksh", "date +%s": str(int(__import__("time").time()))})
    assert not any("ksh" in n for n in preflight.run(ok, RemoteEnvironment(os="linux", privileged=True), native=[],
                                                     has_bundles=True, interpreters=["ksh"]))
