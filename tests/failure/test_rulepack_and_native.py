"""룰팩·텍스트리포트 파서·네이티브 실행기 실패 케이스.

- 조치형(write)/미선언 번들은 로드 거부되고 목록에 남는다(§9, G-30).
- 스크립트 해시 불일치는 실행을 막는다(무결성).
- 파서: 브래킷/파이프 두 형식, 요약 블록 무시, 미등록 판정은 UNKNOWN.
- 네이티브: 플랫폼 불일치 → SKIPPED, 룰 예외 → ERROR(FAIL 아님), 판정은 decide() 경유.
"""
import hashlib
from pathlib import Path

import yaml

from infraguard.core.models import RemoteEnvironment
from infraguard.core.status import Status
from infraguard.orchestrator.native_runner import run_native
from infraguard.parsing.report_txt import parse_report_bytes
from infraguard.result.engine import normalize
from infraguard.rulepack import loader
from infraguard.rules import REGISTRY, NativeOutcome, NativeRule
from infraguard.transport.base import CleanupReport, Connection, ExecResult

# 실제 스크립트 순서: 근거(>>) 먼저, 판정 헤더가 마지막. 구분선은 헤더 직전에 온다.
REPORT = """
===== 1. 계정 관리 =====
    >> rlogin=false

------------------------------------------------------------------------
[양호]  U-01(상)  root 계정 원격 접속 제한
    >> minlen=5
    >> root:$6$abcdefgh$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:19000

------------------------------------------------------------------------
[취약]  U-02(상)  비밀번호 관리정책 설정

------------------------------------------------------------------------
[수동]  U-03(상)  계정 잠금 임계값

------------------------------------------------------------------------
[N/A]   U-29(하)  hosts.lpd
D-02 | 양호 | 데모/샘플 계정 없음
    >> /manager 접근 가능
WEB-01(tomcat) | 취약 | 관리자 페이지 노출
WEB-01(ohs) | 양호 | 해당 없음
X-99 | 보류 | 이상한 어휘
########################################################################
# 점검 요약
#   [양호] GOOD   : 99
"""


def test_report_parser_both_formats_and_summary_ignored():
    r = parse_report_bytes(REPORT.encode("utf-8"), artifact="r.txt", bundle_id="b")
    assert r.ok
    by = {(f.rule_id, f.extra.get("product", "")): f for f in r.findings}
    assert by[("U-01", "")].verdict_raw == "양호" and by[("U-01", "")].severity_raw == "상"
    assert by[("U-01", "")].evidence_raw == "rlogin=false"          # 헤더 앞 근거가 귀속
    assert "minlen=5" in by[("U-02", "")].evidence_raw               # 다음 항목으로 안 샘
    assert by[("U-03", "")].evidence_raw is None
    assert by[("U-29", "")].verdict_raw == "N/A"
    assert by[("D-02", "")].verdict_raw == "양호" and "데모" in by[("D-02", "")].evidence_raw
    assert by[("WEB-01", "tomcat")].verdict_raw == "취약"
    assert "/manager" in by[("WEB-01", "tomcat")].evidence_raw     # 파이프형도 앞 근거 귀속
    assert "관리자 페이지" in by[("WEB-01", "tomcat")].evidence_raw  # 인라인 텍스트 포함
    assert by[("WEB-01", "ohs")].verdict_raw == "양호"
    # 요약 블록의 "[양호] GOOD : 99" 는 판정으로 잡히지 않는다
    assert all(f.rule_id != "GOOD" for f in r.findings)
    assert len(r.findings) == 8


def test_report_parser_results_go_through_decide_and_mask():
    r = parse_report_bytes(REPORT.encode("utf-8"), artifact="r.txt")
    results, _ = normalize(r.findings)
    by = {c.rule_id: c for c in results}
    assert by["U-01"].status is Status.PASS
    assert by["U-02"].status is Status.FAIL
    assert by["U-03"].status is Status.UNKNOWN
    assert by["U-29"].status is Status.SKIPPED
    assert by["X-99"].status is Status.UNKNOWN and "unmapped" in by["X-99"].reason
    assert "$6$" not in (by["U-02"].evidence or "") and "***HASH***" in by["U-02"].evidence


def test_report_parser_non_report_fails_loudly():
    assert not parse_report_bytes(b"just some log\nno verdicts\n").ok


def _pack(tmp_path: Path, bundles: list[dict]) -> Path:
    d = tmp_path / "pk"
    (d / "scripts").mkdir(parents=True)
    for b in bundles:
        (d / b["script"]).write_text("#!/bin/sh\necho hi\n")
        if b.get("sha256") == "AUTO":
            b["sha256"] = hashlib.sha256((d / b["script"]).read_bytes()).hexdigest()
    (d / "manifest.yaml").write_text(
        yaml.safe_dump({"name": "t", "version": "1", "bundles": bundles}, allow_unicode=True),
        encoding="utf-8")
    return d


def test_write_bundle_refused_and_listed(tmp_path):
    d = _pack(tmp_path, [
        {"id": "ok", "script": "scripts/ok.sh", "sha256": "AUTO", "side_effects": "read"},
        {"id": "fix", "script": "scripts/fix.sh", "sha256": "AUTO", "side_effects": "write"},
        {"id": "nodecl", "script": "scripts/n.sh", "sha256": "AUTO"},
    ])
    pk = loader.load(d)
    assert "ok" in pk.bundles
    assert "fix" not in pk.bundles and "nodecl" not in pk.bundles
    assert any("fix" in p and "write" in p for p in pk.problems)
    assert any("nodecl" in p for p in pk.problems)
    assert not pk.runnable


def test_hash_mismatch_blocks_execution(tmp_path):
    d = _pack(tmp_path, [{"id": "b", "script": "scripts/b.sh", "sha256": "0" * 64,
                          "side_effects": "read"}])
    pk = loader.load(d)
    assert not pk.integrity_ok and not pk.runnable
    assert any("SHA-256" in p for p in pk.problems)


class _Conn(Connection):
    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs

    def connect(self): ...
    def probe(self): return RemoteEnvironment(os="linux")
    def exec(self, argv, **kw):
        cmd = argv[-1]
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        return ExecResult(argv, 1, "", "", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def test_native_platform_mismatch_is_skipped_not_pass():
    REGISTRY["T-AIX"] = NativeRule("T-AIX", "aix only", "상", ("aix",),
                                   lambda c, e: NativeOutcome("GOOD", "x"))
    try:
        findings, errors = run_native(_Conn({}), RemoteEnvironment(os="linux"), ["T-AIX"])
        assert not findings and errors[0].status is Status.SKIPPED
    finally:
        REGISTRY.pop("T-AIX", None)


def test_native_rule_exception_is_error_not_fail():
    def boom(c, e):
        raise RuntimeError("kaboom")
    REGISTRY["T-BOOM"] = NativeRule("T-BOOM", "boom", "상", ("linux",), boom)
    try:
        findings, errors = run_native(_Conn({}), RemoteEnvironment(os="linux"), ["T-BOOM"])
        assert not findings
        assert errors[0].status is Status.ERROR and "kaboom" in errors[0].reason
    finally:
        REGISTRY.pop("T-BOOM", None)


def test_native_u05_and_u01_flow_through_decide():
    conn = _Conn({
        "$3 == 0": "root\nbackdoor\n",
        "PermitRootLogin": "PermitRootLogin no\n",
    })
    findings, errors = run_native(conn, RemoteEnvironment(os="linux"), ["U-05", "U-01"])
    assert not errors
    results, _ = normalize(findings)
    by = {c.rule_id: c for c in results}
    assert by["U-05"].status is Status.FAIL and "backdoor" in by["U-05"].evidence
    assert by["U-01"].status is Status.PASS


def test_unknown_native_rule_is_error():
    _, errors = run_native(_Conn({}), RemoteEnvironment(os="linux"), ["U-999"])
    assert errors and errors[0].status is Status.ERROR
