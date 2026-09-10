"""서비스·로그 묶음 YAML 룰(U-34~U-63, U-65~U-67) — 대표 판정과 N/A·MANUAL 구분."""
import pathlib

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import declarative
from infraguard.rules.declarative import evaluate
from infraguard.transport.base import CleanupReport, Connection, ExecResult

PACK = pathlib.Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"
ENV = RemoteEnvironment(os="linux")


class _Conn(Connection):
    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs

    def connect(self): ...
    def probe(self): return ENV
    def exec(self, argv, **kw):
        cmd = argv[-1]
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        return ExecResult(argv, 0, "", "", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


def _v(rid: str, outputs: dict) -> str:
    spec = declarative.load_file(PACK / "rules" / f"{rid}.yaml")
    return evaluate(spec, _Conn(outputs), ENV).verdict_raw


def test_all_service_rules_exist_and_load():
    ids = [f"U-{i:02d}" for i in range(34, 64)] + ["U-65", "U-66", "U-67"]
    for rid in ids:
        assert declarative.load_file(PACK / "rules" / f"{rid}.yaml").id == rid


def test_inetd_style_services_vuln_when_active():
    for rid in ("U-34", "U-36", "U-38", "U-44", "U-52"):
        assert _v(rid, {}) == "GOOD", rid
        assert _v(rid, {"inetd.conf": "proc: telnetd\n"}) == "VULN", rid


def test_daemon_absent_is_na_not_pass():
    # 데몬이 없으면 설정 항목은 '해당없음'. 양호로 부풀리지 않는다.
    for rid in ("U-45", "U-46", "U-47", "U-48", "U-49", "U-50", "U-51", "U-53", "U-56", "U-57", "U-59", "U-60", "U-61"):
        assert _v(rid, {}) == "NA", rid


def test_dns_zone_transfer_and_update():
    named = {"named|named-pkcs11": "named\n"}
    assert _v("U-50", {**named, "allow-transfer": "allow-transfer { 10.0.0.2; };\n"}) == "GOOD"
    assert _v("U-50", {**named, "allow-transfer": "allow-transfer { any; };\n"}) == "VULN"
    assert _v("U-50", {**named, "allow-transfer": ""}) == "VULN"          # 미설정 = 취약
    assert _v("U-51", {**named, "allow-update": "allow-update { any; };\n"}) == "VULN"
    assert _v("U-51", {**named, "allow-update": ""}) == "GOOD"


def test_mail_rules():
    mta = {"sendmail|postfix": "postfix\nmaster\n"}
    assert _v("U-48", {**mta, "disable_vrfy_command": "yes\n"}) == "GOOD"
    assert _v("U-48", {**mta, "disable_vrfy_command": "no\n"}) == "VULN"
    assert _v("U-47", {**mta, "smtpd_relay_restrictions": "permit_mynetworks, reject_unauth_destination\n"}) == "GOOD"
    assert _v("U-47", {**mta, "smtpd_relay_restrictions": "promiscuous_relay\n"}) == "VULN"
    sm = {"sendmail|postfix": "sendmail\n", "grep -x sendmail": "sendmail\n"}
    assert _v("U-46", {**sm, "PrivacyOptions": "O PrivacyOptions=authwarnings,restrictqrun\n"}) == "GOOD"
    assert _v("U-46", {**sm, "PrivacyOptions": "O PrivacyOptions=authwarnings\n"}) == "VULN"
    assert _v("U-46", {"sendmail|postfix": "postfix\n"}) == "NA"          # postfix 는 해당 없음


def test_snmp_rules():
    snmp = {"grep -xE '(snmpd": "proc: snmpd\n"}   # 프로세스 조회 전용 키 (설정파일 경로 /etc/snmp/snmpd.conf 와 충돌 방지)
    assert _v("U-59", {**snmp, "r[ow]community6?|com2sec|community": "rocommunity public\n"}) == "VULN"
    assert _v("U-59", {**snmp, "r[ow]user|createUser": "rouser admin priv\n"}) == "GOOD"
    assert _v("U-60", {**snmp, "r[ow]community6?|com2sec|community": "rocommunity public 10.0.0.0/8\n"}) == "VULN"
    assert _v("U-60", {**snmp, "r[ow]community6?|com2sec|community": "rocommunity Xk9!qz 10.0.0.0/8\n"}) == "MANUAL"
    assert _v("U-61", {**snmp, "r[ow]community6?|com2sec": "rocommunity Xk9!qz\n"}) == "VULN"       # 소스 제한 없음
    assert _v("U-61", {**snmp, "r[ow]community6?|com2sec": "rocommunity Xk9!qz 10.0.0.0/8\n"}) == "GOOD"
    assert _v("U-61", {**snmp, "r[ow]community6?|com2sec": "rocommunity Xk9!qz default\n"}) == "VULN"


def test_ftp_rules():
    assert _v("U-55", {"^ftp:": "ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\n"}) == "GOOD"
    assert _v("U-55", {"^ftp:": "ftp:x:14:50:FTP User:/var/ftp:/bin/bash\n"}) == "VULN"
    assert _v("U-55", {}) == "NA"
    ftp = {"vsftpd|proftpd": "proc: vsftpd\n"}
    assert _v("U-54", ftp) == "VULN"
    assert _v("U-57", {**ftp, "^root$": "root\n"}) == "GOOD"
    assert _v("U-57", {**ftp, "^root$": ""}) == "VULN"


def test_nfs_export_control():
    nfs = {"nfsd|rpc.mountd": "proc: nfsd\n"}
    assert _v("U-40", {}) == "NA"
    assert _v("U-40", {**nfs, "grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports": "/data 10.0.0.0/24(ro)\n"}) == "GOOD"
    assert _v("U-40", {**nfs, "grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports": "/data *(rw,no_root_squash)\n",
                       "no_root_squash": "/data *(rw,no_root_squash)\n"}) == "VULN"


def test_banner_ntp_logging():
    assert _v("U-62", {"/etc/issue": "/etc/issue: Authorized use only. Activity is monitored.\n"}) == "GOOD"
    assert _v("U-62", {}) == "VULN"
    # 배포판 기본 배너(OS 이름만)는 경고문이 아니다 → 취약 (WSL 실측에서 양호로 나오던 오탐)
    assert _v("U-62", {"/etc/issue": "/etc/issue: Ubuntu 24.04.4 LTS \\n \\l\n"}) == "VULN"
    assert _v("U-62", {"/etc/issue": "/etc/issue: Ubuntu 24.04.4 LTS \\n \\l\n", "Banner": "Banner /etc/issue.net\n"}) == "GOOD"


def test_manual_flag_does_not_override_na():
    """데몬이 없으면 N/A 여야 한다 — manual 플래그가 수동확인으로 덮으면 안 됨(실측 오탐)."""
    for rid in ("U-45", "U-49", "U-56"):
        spec = declarative.load_file(PACK / "rules" / f"{rid}.yaml")
        assert not spec.manual, rid
        assert _v(rid, {}) == "NA", rid
    assert _v("U-65", {"chronyd|ntpd": "chronyd\n"}) == "GOOD"
    assert _v("U-65", {}) == "VULN"
    assert _v("U-66", {"rsyslogd|syslogd": "rsyslogd\n", "rsyslog.conf": "auth,authpriv.* /var/log/auth.log\n"}) == "GOOD"
    assert _v("U-66", {}) == "VULN"
    assert _v("U-67", {"find /var/log": ""}) == "GOOD"
    assert _v("U-67", {"find /var/log": "/var/log/x\n"}) == "VULN"
