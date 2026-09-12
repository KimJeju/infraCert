"""스캔 워커 — 스레딩 모델의 핵심 제약을 지킨다(§3).

절대 금지:
  - 이 파일에서 위젯을 만지지 않는다 (QtCore 만 import). 정적 테스트가 강제한다.
  - Secret 을 시그널 페이로드에 싣지 않는다. cred_id 만 다니고, Credential 객체는
    생성자 인자로 워커에 직접 전달된다(시그널 경유 아님).
  - reveal() 을 호출하지 않는다 (transport 계층에서만).
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, Signal

from infraguard.assets.models import Host
from infraguard.core.models import HostResult, Platform
from infraguard.credentials.session import Credential
from infraguard.orchestrator.host_scan import HostJob, scan_host
from infraguard.orchestrator.remote_runner import RunSpec, validate_env
from infraguard.orchestrator.results_store import ResultsStore
from infraguard.parsing.legacy_csv import Profile as CsvProfile
from infraguard.rulepack.loader import Profile, RulePack
from infraguard.transport.base import Connection
from infraguard.transport.netdev import NetdevConnection, NetdevTarget
from infraguard.transport.ssh import SSHConnection, SSHTarget
from infraguard.transport.winrm import WinRMConnection, WinRMTarget

# 진행 바용 단계 순서 (§5.1 코어스)
log = logging.getLogger(__name__)

STAGES = ["연결 중", "환경 점검", "실행 중", "산출물 회수", "파싱", "네이티브 점검", "완료"]


def build_job(pack: RulePack, profile: Profile, *, timeout: int | None = None,
              host_params: dict[str, str] | None = None, preflight: bool = True) -> HostJob:
    """룰팩 프로파일 → HostJob. 번들 스크립트는 룰팩에서, 네이티브는 앱 레지스트리에서.

    host_params: 호스트에 저장된 파라미터. 번들이 manifest 에 선언한 이름만 환경변수로 넘긴다.
    """
    bundles = []
    hp = host_params or {}
    missing: list[str] = []
    for bid in profile.bundles:
        b = pack.bundles.get(bid)
        if b is None:
            continue
        env = {n: hp[n] for n in b.param_names if hp.get(n)}
        missing += [n for n in b.param_names if n not in env]
        spec = RunSpec(bundle_id=b.id, script=b.script, args=list(b.args),
                       timeout=timeout or b.timeout, interpreter=b.interpreter,
                       extra_files=list(b.extra_files), env=env)
        bundles.append((spec, list(b.provides)))
    validate_env(hp)                       # 저장 시 검사했지만 실행 직전에 한 번 더
    return HostJob(bundles=bundles, native=list(profile.native),
                   manual_rules=pack.manual_rules(), exclude=set(profile.exclude), params=dict(hp),
                   preflight=preflight, missing_params=missing)


class HostKeyBridge(QObject):
    """호스트키 승인을 UI 스레드로 넘겨 blocking 대기한다(§5.3). lock 으로 직렬화."""

    request = Signal(str, str, str)  # host, key_type, fingerprint

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._result = False

    def ask(self, host: str, key_type: str, fingerprint: str) -> bool:
        with self._lock:
            self._event.clear()
            self._result = False
            self.request.emit(host, key_type, fingerprint)
            self._event.wait()
            return self._result

    def answer(self, ok: bool) -> None:
        self._result = bool(ok)
        self._event.set()


def build_connection(host: Host, cred: Credential, approve) -> Connection:  # noqa: ANN001
    """Host + Credential → 플랫폼별 Connection. reveal() 은 여기서 하지 않는다.

    windows/pc → WinRM(포트 22 그대로면 5985 로), network → 장비 셸(SSH invoke_shell), 그 외 → SSH.
    """
    if host.platform in (Platform.WINDOWS, Platform.PC):
        port = 5985 if host.port == 22 else host.port
        return WinRMConnection(WinRMTarget(host=host.address, port=port, credential=cred, use_ssl=port == 5986))
    if host.platform == Platform.NETWORK:
        return NetdevConnection(NetdevTarget(host=host.address, port=host.port, credential=cred),
                                approve_host_key=approve)
    target = SSHTarget(host=host.address, port=host.port, credential=cred)
    bastion = None
    if host.use_bastion and host.bastion_host:
        b_cred = Credential(
            cred_id=cred.cred_id, username=host.bastion_user or cred.username,
            kind=cred.kind, password=cred.password, key_path=cred.key_path,
            key_passphrase=cred.key_passphrase,
        )
        bastion = SSHTarget(host=host.bastion_host, port=host.bastion_port, credential=b_cred)
    return SSHConnection(target, bastion=bastion, approve_host_key=approve)


class ScanWorker(QObject):
    """호스트 1대 진단. QThread 에 moveToThread 한다."""

    started = Signal(str)
    stage_changed = Signal(str, str)
    progress = Signal(str, int, int)
    host_finished = Signal(str, object)   # host_id, HostResult
    failed = Signal(str, str)
    log = Signal(str, str)
    done = Signal(str)

    def __init__(self, host: Host, cred: Credential, job: HostJob, local_dir: Path,
                 bridge: HostKeyBridge, profiles: list[CsvProfile] | None = None) -> None:
        super().__init__()
        self._host = host
        self._cred = cred                # 시그널이 아니라 인자로 받음
        self._job = job
        self._local_dir = local_dir
        self._bridge = bridge
        self._profiles = profiles
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        hid = self._host.host_id
        self.started.emit(hid)
        try:
            conn = build_connection(self._host, self._cred, self._bridge.ask)

            def prog(stage: str) -> None:
                self.stage_changed.emit(hid, stage)
                self.log.emit(hid, f"[{stage}]")
                base = stage.split(" (")[0].split(" U-")[0].split(" D-")[0]
                for i, s in enumerate(STAGES, start=1):
                    if base.startswith(s):
                        self.progress.emit(hid, i, len(STAGES))
                        break

            host = scan_host(
                conn, self._job, self._local_dir,
                host_id=hid, hostname=self._host.label, address=self._host.address,
                profiles=self._profiles, progress=prog, should_cancel=self._cancel.is_set,
            )
            host.asset = self._host.asset_snapshot()
            self.host_finished.emit(hid, host)
        except Exception as e:  # noqa: BLE001 - 워커 예외 격리
            self.failed.emit(hid, f"{type(e).__name__}: {e}")
        finally:
            self.done.emit(hid)


class ScanController(QObject):
    """여러 ScanWorker 를 동시성 제한 하에 굴린다. 호스트 실패는 격리된다."""

    scan_started = Signal(str)
    scan_progress = Signal(int, int)
    scan_finished = Signal(object)      # ScanResult

    host_started = Signal(str)
    host_stage = Signal(str, str)
    host_progress = Signal(str, int, int)
    host_result = Signal(str, object)   # host_id, HostResult (체크포인트 후)
    host_failed = Signal(str, str)
    log = Signal(str, str)

    def __init__(self) -> None:
        super().__init__()
        self.host_key_bridge = HostKeyBridge()
        self._threads: dict[str, QThread] = {}
        self._workers: dict[str, ScanWorker] = {}
        self._queue: list[tuple[Host, Credential, HostJob]] = []
        self._active = 0
        self._done = 0
        self._total = 0
        self._concurrency = 5
        self._scan_id = ""
        self._store: ResultsStore | None = None
        self._local_root = Path(".")
        self._profiles: list[CsvProfile] | None = None
        self._zombies: list[tuple[QThread, ScanWorker | None]] = []   # 종료 안 된 스레드 참조 보관(GC 방지)

    @property
    def running(self) -> bool:
        return self._active > 0 or bool(self._queue)

    def start(self, jobs: list[tuple[Host, Credential, HostJob]], *, scan_id: str,
              store: ResultsStore, local_root: Path, concurrency: int = 5,
              profiles: list[CsvProfile] | None = None) -> None:
        self._queue = list(jobs)
        self._total = len(jobs)
        self._done = 0
        self._active = 0
        self._concurrency = max(1, min(concurrency, 20))
        self._scan_id = scan_id
        self._store = store
        self._local_root = local_root
        self._profiles = profiles
        self.scan_started.emit(scan_id)
        self.scan_progress.emit(0, self._total)
        self._pump()

    def cancel(self) -> None:
        self._queue.clear()
        for w in self._workers.values():
            w.cancel()

    def _pump(self) -> None:
        if not self._queue and self._active == 0:
            self._finish()
            return
        while self._queue and self._active < self._concurrency:
            host, cred, job = self._queue.pop(0)
            self._launch(host, cred, job)

    def _launch(self, host: Host, cred: Credential, job: HostJob) -> None:
        local_dir = self._local_root / host.host_id
        local_dir.mkdir(parents=True, exist_ok=True)
        worker = ScanWorker(host, cred, job, local_dir, self.host_key_bridge, self._profiles)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)

        worker.started.connect(self.host_started)
        worker.stage_changed.connect(self.host_stage)
        worker.progress.connect(self.host_progress)
        worker.failed.connect(self._on_failed)
        worker.host_finished.connect(self._on_host_finished)
        worker.log.connect(self.log)
        # 람다가 아니라 바운드 슬롯이어야 한다. 람다는 워커 스레드에서 직접 호출돼 thread.wait() 가 자기 자신을
        # 기다리다 실패하고, 참조를 놓은 QThread 가 실행 중 GC 돼 qFatal(0xc0000409) 로 앱이 죽는다(09-11 GUI 크래시).
        worker.done.connect(self._on_worker_done)

        self._workers[host.host_id] = worker
        self._threads[host.host_id] = thread
        self._active += 1
        thread.start()

    def _on_host_finished(self, host_id: str, host: HostResult) -> None:
        if self._store is not None:      # 체크포인트: 즉시 기록
            self._store.save_host(self._scan_id, host)
        self.host_result.emit(host_id, host)

    def _on_failed(self, host_id: str, message: str) -> None:
        host = HostResult(host_id=host_id, hostname=host_id, error=message)
        if self._store is not None:
            self._store.save_host(self._scan_id, host)
        self.host_failed.emit(host_id, message)
        self.host_result.emit(host_id, host)

    def _on_worker_done(self, host_id: str) -> None:
        """메인 스레드(큐 연결)에서 실행된다. 워커 run() 은 이미 끝났으므로 quit/wait 는 즉시 돌아온다."""
        thread = self._threads.get(host_id)
        if thread is not None:
            self._cleanup_thread(host_id, thread)

    def _cleanup_thread(self, host_id: str, thread: QThread) -> None:
        if QThread.currentThread() is thread:          # 방어: 워커 스레드에서 불리면 메인으로 되던진다
            QTimer.singleShot(0, lambda: self._cleanup_thread(host_id, thread))
            return
        thread.quit()
        if not thread.wait(5000):
            log.error("scan thread %s did not stop in 5s — keeping reference to avoid fatal", host_id)
            thread.finished.connect(thread.deleteLater)
            self._zombies.append((thread, self._workers.get(host_id)))
        self._workers.pop(host_id, None)
        self._threads.pop(host_id, None)
        self._active -= 1
        self._done += 1
        self.scan_progress.emit(self._done, self._total)
        self._pump()

    def _finish(self) -> None:
        if self._store is None:
            return
        self._store.finish_scan(self._scan_id, datetime.now(UTC))
        scan = self._store.load_scan(self._scan_id)
        if scan is not None:
            self.scan_finished.emit(scan)
