"""ScanController 스레드 정리 — 워커 완료 처리가 메인 스레드에서 돌고 QThread 가 실행 중 GC 되지 않는다.

09-11 GUI 크래시(Qt6Core 0xc0000409): done 시그널을 람다에 물려 워커 스레드에서 thread.wait() 를 자기 자신에게 걸고
참조를 놓아 QThread 가 실행 중 파괴됐다. 이 테스트는 실제 QThread 로 그 경로를 태운다.
"""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread  # noqa: E402

from infraguard.assets.models import Host  # noqa: E402
from infraguard.core.models import RemoteEnvironment  # noqa: E402
from infraguard.credentials.secret import Secret  # noqa: E402
from infraguard.credentials.session import Credential  # noqa: E402
from infraguard.orchestrator.host_scan import HostJob  # noqa: E402
from infraguard.orchestrator.results_store import ResultsStore  # noqa: E402
from infraguard.transport.base import CleanupReport, Connection, ExecResult  # noqa: E402
from infraguard.ui import workers  # noqa: E402


class _Conn(Connection):
    def connect(self) -> None: ...
    def probe(self) -> RemoteEnvironment: return RemoteEnvironment(os="linux")
    def exec(self, argv, *, timeout, cwd=None, stdin_data=None, max_output=1 << 20):  # noqa: ANN001,ANN201
        return ExecResult(list(argv), 0, "", "", 1)
    def upload(self, local, remote): ...  # noqa: ANN001
    def download(self, remote, local): ...  # noqa: ANN001
    def cleanup(self, paths): return CleanupReport()  # noqa: ANN001
    def close(self) -> None: ...


def test_worker_done_cleanup_runs_on_main_thread_and_frees_threads(qtbot, tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(workers, "build_connection", lambda host, cred, approve: _Conn())
    ctl = workers.ScanController()
    seen: list[QThread] = []
    orig = ctl._cleanup_thread

    def spy(host_id: str, thread: QThread) -> None:
        seen.append(QThread.currentThread())
        orig(host_id, thread)

    monkeypatch.setattr(ctl, "_cleanup_thread", spy)
    store = ResultsStore(tmp_path / "results.db")
    from datetime import datetime  # noqa: PLC0415

    from infraguard.core.models import ScanResult  # noqa: PLC0415
    store.start_scan(ScanResult(scan_id="s1", engine_version="t", started_at=datetime.now()))
    cred = Credential(cred_id="c", username="u", kind="password", password=Secret("p"))
    hosts = [Host(host_id=f"h{i}", name=f"h{i}", address="10.0.0.1", platform="linux") for i in range(3)]
    jobs = [(h, cred, HostJob()) for h in hosts]

    with qtbot.waitSignal(ctl.scan_finished, timeout=15000):
        ctl.start(jobs, scan_id="s1", store=store, local_root=tmp_path / "scan", concurrency=2)

    main = QThread.currentThread()
    assert len(seen) == 3 and all(t is main for t in seen)     # 정리는 전부 메인 스레드에서
    assert not ctl._threads and not ctl._workers and not ctl._zombies
    assert not ctl.running
    store.close()
