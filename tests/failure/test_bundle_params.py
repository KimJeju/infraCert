"""번들 파라미터(환경변수) — 인젝션 원천 차단, 선언된 이름만 전달, 생략 사유 노출."""
import pathlib

import pytest

from infraguard.orchestrator.remote_runner import RemoteRunner, RunSpec, validate_env
from infraguard.parsing.report_txt import parse_report_bytes
from infraguard.rulepack import loader
from infraguard.transport.base import CleanupReport, Connection, ExecResult
from infraguard.ui.workers import build_job

PACK = pathlib.Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


@pytest.mark.parametrize("bad", [
    {"TOMCAT_HOME": "/opt/tomcat; rm -rf /"},
    {"TOMCAT_HOME": "/opt/tomcat$(id)"},
    {"TOMCAT_HOME": "/opt/tom cat"},
    {"TOMCAT_HOME": "'/opt/tomcat'"},
    {"tomcat_home": "/opt/tomcat"},        # 소문자 이름
    {"X;Y": "1"},
])
def test_env_with_shell_metacharacters_is_rejected(bad):
    with pytest.raises(ValueError):
        validate_env(bad)


def test_env_with_path_characters_is_accepted():
    validate_env({"TOMCAT_HOME": "/opt/tomcat-9.0", "ORACLE_SID": "ORCL", "WL_DOMAIN_HOME": "/u01/user_projects/domains/base_domain"})


class _Recorder(Connection):
    def __init__(self):
        self.cmds: list[str] = []

    def connect(self): ...
    def probe(self): ...
    def exec(self, argv, **kw):
        self.cmds.append(argv[-1])
        return ExecResult(argv, 0, "12345\n", "", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def test_launch_prefixes_env_before_script(tmp_path):
    (tmp_path / "s.sh").write_text("echo")
    conn = _Recorder()
    spec = RunSpec(bundle_id="b", script=tmp_path / "s.sh", interpreter="ksh",
                   env={"TOMCAT_HOME": "/opt/tomcat", "ORACLE_SID": "ORCL"})
    RemoteRunner(conn)._launch(spec, "/tmp/infraguard-x")
    cmd = conn.cmds[-1]
    assert "TOMCAT_HOME=/opt/tomcat ORACLE_SID=ORCL ksh /tmp/infraguard-x/s.sh" in cmd


def test_launch_refuses_bad_env(tmp_path):
    (tmp_path / "s.sh").write_text("echo")
    spec = RunSpec(bundle_id="b", script=tmp_path / "s.sh", env={"A": "x;y"})
    with pytest.raises(ValueError):
        RemoteRunner(_Recorder())._launch(spec, "/tmp/infraguard-x")


def test_build_job_passes_only_declared_params():
    pk = loader.load(PACK)
    assert pk.bundles["web-was"].param_names == ["TOMCAT_HOME", "OHS_CONF_DIR", "WL_DOMAIN_HOME"]
    job = build_job(pk, pk.profiles["web-was"],
                    host_params={"TOMCAT_HOME": "/opt/tomcat", "ORACLE_SID": "ORCL", "EVIL": "x"})
    spec, _ = job.bundles[0]
    assert spec.env == {"TOMCAT_HOME": "/opt/tomcat"}     # 선언 안 된 이름은 버린다


def test_skip_lines_surface_reason_when_nothing_reported():
    txt = ("# header\n\\n[skip] TOMCAT_HOME 미지정 - Tomcat 점검 생략\n"
           "\\n[skip] OHS_CONF_DIR 미지정 - WebTier/OHS 점검 생략\n# 점검 요약\n")
    r = parse_report_bytes(txt.encode("utf-8"), artifact="w.txt")
    assert not r.ok
    assert "TOMCAT_HOME 미지정" in r.error and "OHS_CONF_DIR" in r.error
    assert sum("[skip]" in w for w in r.warnings) == 2
