"""계정·파일 묶음 YAML 룰(U-07~U-33) — 대표 케이스가 기대 판정을 내고 추측하지 않는다."""
import pathlib

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import declarative
from infraguard.rules.declarative import evaluate
from infraguard.transport.base import CleanupReport, Connection, ExecResult

PACK = pathlib.Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"
ENV = RemoteEnvironment(os="linux")


class _Conn(Connection):
    """키 순서대로 첫 매치. fail 에 든 키는 실패(ok=False, 빈 출력)."""

    def __init__(self, outputs: dict[str, str], fail: set[str] = frozenset()):
        self.outputs, self.fail = outputs, fail

    def connect(self): ...
    def probe(self): return ENV
    def exec(self, argv, **kw):
        cmd = argv[-1]
        for k in self.fail:
            if k in cmd:
                return ExecResult(argv, 1, "", "denied", 1, error="denied")
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        return ExecResult(argv, 0, "", "", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def _rule(rid: str):
    return declarative.load_file(PACK / "rules" / f"{rid}.yaml")


def _v(rid: str, outputs: dict, fail: set = frozenset()) -> str:
    return evaluate(_rule(rid), _Conn(outputs, fail), ENV).verdict_raw


def test_all_batch_files_load_and_ids_match_filenames():
    for f in sorted((PACK / "rules").glob("U-*.yaml")):
        assert declarative.load_file(f).id == f.stem, f.name


def test_u10_duplicate_uid():
    assert _v("U-10", {"uniq -d": ""}) == "GOOD"
    assert _v("U-10", {"uniq -d": "1001\n", "awk -F: -v": "alice:1001\nbob:1001\n"}) == "VULN"
    assert _v("U-10", {}, fail={"cut -d:"}) == "MANUAL"     # /etc/passwd 읽기 실패는 추측 안 함


def test_u12_tmout():
    assert _v("U-12", {"TMOUT": "export TMOUT=600\n"}) == "GOOD"
    assert _v("U-12", {"TMOUT": "TMOUT=3600\n"}) == "VULN"
    assert _v("U-12", {"TMOUT": ""}) == "VULN"                # 미설정 = 취약(가이드)
    assert _v("U-12", {"TMOUT": "TMOUT=$SOMEVAR\n"}) == "MANUAL"  # 값 해석 불가 → 수동


def test_u13_encrypt_method():
    assert _v("U-13", {"ENCRYPT_METHOD": "ENCRYPT_METHOD SHA512\n"}) == "GOOD"
    assert _v("U-13", {"ENCRYPT_METHOD": "ENCRYPT_METHOD MD5\n"}) == "VULN"
    assert _v("U-13", {"ENCRYPT_METHOD": ""}) == "MANUAL"


def test_u14_root_path_dot():
    assert _v("U-14", {"PATH": "PATH=/usr/bin:/bin\n"}) == "GOOD"
    assert _v("U-14", {"PATH": "PATH=/usr/bin:.:/bin\n"}) == "VULN"
    assert _v("U-14", {"PATH": "export PATH=/usr/bin::/bin\n"}) == "VULN"
    assert _v("U-14", {"PATH": "PATH=$PATH:/usr/local/bin\n"}) == "GOOD"   # '$PATH:' 는 '.' 아님
    assert _v("U-14", {"PATH": ""}) == "MANUAL"                             # /root 읽기 불가


def test_u27_rhosts():
    assert _v("U-27", {"ls -l": ""}) == "GOOD"
    assert _v("U-27", {"ls -l": "-rw-r--r-- 1 root root 3 /etc/hosts.equiv\n", "grep -lE": "/etc/hosts.equiv\n"}) == "VULN"
    assert _v("U-27", {"ls -l": "-rw-r--r-- 1 root root 3 /etc/hosts.equiv\n", "grep -lE": ""}) == "MANUAL"


def test_u08_root_group_members():
    assert _v("U-08", {"$3 == 0 {print}": "root:x:0:\n", "$4 != ": ""}) == "GOOD"
    assert _v("U-08", {"$3 == 0 {print}": "root:x:0:alice\n", "$4 != ": "alice\n"}) == "VULN"


def test_find_based_rules_manual_on_failure_not_pass():
    # find 가 실패(권한)하고 출력도 없으면 GOOD 이 아니라 MANUAL
    for rid in ("U-15", "U-17", "U-24", "U-26"):
        assert _v(rid, {}, fail={"find"}) == "MANUAL", rid
        assert _v(rid, {"find": ""}) == "GOOD", rid
        assert _v(rid, {"find": "/x\n"}) == "VULN", rid
    for rid in ("U-23", "U-33"):
        assert _v(rid, {"find": "/usr/bin/passwd\n"}) == "MANUAL", rid   # 목록은 판단 대상


def test_u28_is_always_manual_with_evidence():
    out = evaluate(_rule("U-28"), _Conn({"hosts.deny": "ALL: ALL\n", "ss -ltn": "LISTEN 0.0.0.0:22\n"}), ENV)
    assert out.verdict_raw == "MANUAL" and "ALL: ALL" in out.evidence and "LISTEN" in out.evidence
