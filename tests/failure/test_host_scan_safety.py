"""호스트 스캔 파이프라인 안전성(§14).

- 회수 아카이브의 경로 이탈 멤버를 해제하지 않는다(path traversal).
- 연결 실패가 예외로 터지지 않고 HostResult.error 로 격리된다(호스트 실패 격리).
- 실행오류가 취약(FAIL)으로 집계되지 않는다.
- 번들 실행 실패 시 provides 항목이 UNKNOWN 으로 드러난다(조용히 사라지지 않음).
"""
import io
import tarfile
from pathlib import Path

from infraguard.core.models import CheckResult, HostResult, RemoteEnvironment
from infraguard.core.status import Status
from infraguard.orchestrator.host_scan import HostJob, safe_extract, scan_host
from infraguard.orchestrator.remote_runner import RunSpec
from infraguard.transport.base import CleanupReport, Connection, ExecResult, TransportError


def test_safe_extract_blocks_traversal(tmp_path: Path):
    arc = tmp_path / "a.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        for name, body in [("result.csv", b"code\nU-01\n"), ("../evil.txt", b"x"),
                           ("sub/nested.csv", b"y")]:
            ti = tarfile.TarInfo(name)
            ti.size = len(body)
            tf.addfile(ti, io.BytesIO(body))
    files = {f.name for f in safe_extract(arc, tmp_path / "ext")}
    assert "result.csv" in files and "nested.csv" in files
    assert not (tmp_path / "evil.txt").exists(), "경로 이탈 멤버가 해제됐다"


class _FailingConn(Connection):
    def __init__(self):
        self.closed = False

    def connect(self):
        raise TransportError("connection refused")

    def probe(self): ...
    def exec(self, argv, **kw):
        return ExecResult(argv, None, "", "", 0, error="not connected")

    def upload(self, local, remote): ...
    def download(self, remote, local): ...
    def cleanup(self, paths):
        return CleanupReport()

    def close(self):
        self.closed = True


def test_connection_failure_is_isolated(tmp_path: Path):
    conn = _FailingConn()
    (tmp_path / "x.sh").write_text("echo hi")
    job = HostJob(bundles=[(RunSpec(bundle_id="b", script=tmp_path / "x.sh"), ["U-01"])])
    host = scan_host(conn, job, tmp_path, host_id="H1", hostname="web01")
    assert isinstance(host, HostResult)
    assert host.error and "connection refused" in host.error
    assert host.results == []
    assert conn.closed, "실패해도 close() 는 호출돼야 한다"


class _DeadAfterConnect(Connection):
    """연결은 되지만 원격 작업 디렉터리 생성부터 실패하는 서버."""

    def connect(self): ...
    def probe(self): return RemoteEnvironment(os="linux")
    def exec(self, argv, **kw):
        return ExecResult(argv, 1, "", "mktemp: denied", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def test_bundle_failure_surfaces_provides_as_unknown(tmp_path: Path):
    (tmp_path / "x.sh").write_text("echo hi")
    job = HostJob(bundles=[(RunSpec(bundle_id="b", script=tmp_path / "x.sh"), ["U-01", "U-02"])])
    host = scan_host(_DeadAfterConnect(), job, tmp_path, host_id="H1", hostname="web01")
    assert host.error and "[b]" in host.error
    by = {r.rule_id: r.status for r in host.results}
    assert by == {"U-01": Status.UNKNOWN, "U-02": Status.UNKNOWN}
    assert Status.PASS not in by.values() and Status.FAIL not in by.values()


def test_error_not_counted_as_fail():
    host = HostResult(
        host_id="H1", hostname="web01",
        results=[
            CheckResult(rule_id="U-01", name="a", status=Status.FAIL, reason="vuln"),
            CheckResult(rule_id="U-02", name="b", status=Status.ERROR, reason="timeout"),
        ],
    )
    summ = host.summary()
    assert summ[Status.FAIL] == 1 and summ[Status.ERROR] == 1
