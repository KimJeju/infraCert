"""Oracle DB 선언형 룰 생성기 — D-01~D-26 (KISA 2026 VIII장), DB 호스트에 SSH 로 접속해 sqlplus 조회만.

    python scripts/gen_rules_oracle.py [rulepacks/kisa-2026/rules]

전제: 호스트 파라미터 ORACLE_HOME·ORACLE_SID(자산 편집 → 번들 파라미터) 가 있고, 접속 계정이 OS 인증(`/ as sysdba`)
으로 sqlplus 를 실행할 수 있어야 한다(oracle 계정 또는 dba 그룹). 없으면 sqlplus 오류가 근거에 남고 MANUAL.
모든 SQL 은 SELECT 뿐. MSSQL 전용 항목(D-16/23/24)과 ODBC(D-13)는 Oracle 에서 NA.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ORA = "linux aix solaris hpux".split()
ACC, PERM, OPT, PATCH = "계정관리", "접근관리", "옵션관리", "패치관리"
# sqlplus 래퍼: ORACLE_HOME/SID 는 env 접두(호스트 파라미터)로 온다. 실패·ORA- 는 stdout 에 섞여 나와 규칙이 잡는다.
_SQ = ('export PATH="$ORACLE_HOME/bin:$PATH"; printf "set heading off feedback off pagesize 0 linesize 300 '
       'trimspool on\\n%s\\nexit\\n" \'{sql}\' | sqlplus -S -L / as sysdba 2>&1')
_ERR = {"from": "q", "regex": r"(?P<err>ORA-\d+|SP2-\d+|TNS-\d+|sqlplus: not found|Permission denied)"}
_ERR_STEP = {"when": {"err": {"exists": True}}, "then": "MANUAL"}


def sq(sql: str) -> str:
    return _SQ.format(sql=sql.replace("'", "'\"'\"'"))


def rule(rid: str, name: str, sev: str, cat: str, collect: list[dict], verdict: list[dict], *,
         extract: list[dict] | None = None, note: str = "", manual: bool = False, sqlrule: bool = True) -> dict:
    d: dict = {"id": rid, "name": name, "severity": sev, "category": cat, "platforms": ORA}
    if manual:
        d["manual"] = True
    d["collect"] = collect
    ex = list(extract or [])
    vd = list(verdict)
    if sqlrule and any(c["key"] == "q" for c in collect):
        ex.insert(0, _ERR)
        vd.insert(0, _ERR_STEP)
    if ex:
        d["extract"] = ex
    d["verdict"] = vd
    d["evidence"] = [c["key"] for c in collect]
    if note:
        d["note"] = note
    return d


def c(key: str, cmd: str, timeout: int = 90) -> dict:
    return {"key": key, "cmd": cmd, "timeout": timeout}


SYS_SCHEMAS = ("'SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN','XDB','WMSYS','CTXSYS','MDSYS','ORDSYS','ORDDATA','OLAPSYS',"
               "'EXFSYS','APEX_PUBLIC_USER','ANONYMOUS','DIP','ORACLE_OCM','APPQOSSYS','AUDSYS','GSMADMIN_INTERNAL',"
               "'DBSFWUSER','GGSYS','LBACSYS','OJVMSYS','REMOTE_SCHEDULER_AGENT','SYSBACKUP','SYSDG','SYSKM','SYSRAC',"
               "'SYS$UMF','DVSYS','DVF','MDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','XS$NULL','OJVMSYS'")
DEMO = "'SCOTT','HR','OE','SH','PM','IX','BI','ADAMS','JONES','CLARK','BLAKE'"

RULES: list[dict] = [
    rule("D-01", "기본 계정의 비밀번호, 정책 등을 변경하여 사용", "상", ACC,
         [c("q", sq("SELECT username FROM dba_users_with_defpwd WHERE username IN (SELECT username FROM dba_users WHERE account_status='OPEN');"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "VULN"}],
         note="기본 비밀번호를 그대로 쓰는 OPEN 계정(dba_users_with_defpwd)이 없으면 양호"),
    rule("D-02", "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용", "상", ACC,
         [c("q", sq(f"SELECT username||':'||account_status FROM dba_users WHERE username IN ({DEMO}) AND account_status LIKE 'OPEN%';"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "VULN"}], note="데모 계정이 OPEN 이면 취약"),
    rule("D-03", "비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정", "상", ACC,
         [c("q", sq("SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION');"))],
         [{"when": {"q": {"regex": r"PASSWORD_LIFE_TIME=UNLIMITED|PASSWORD_VERIFY_FUNCTION=NULL"}}, "then": "VULN"},
          {"when": {"q": {"regex": r"PASSWORD_LIFE_TIME=\d+"}}, "then": "GOOD"}, {"else": "MANUAL"}],
         note="DEFAULT 프로파일 기준. 다른 프로파일을 쓰면 별도 확인"),
    rule("D-04", "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용", "상", ACC,
         [c("q", sq("SELECT grantee FROM dba_role_privs WHERE granted_role='DBA' AND grantee NOT IN ('SYS','SYSTEM') AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y');"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}], note="SYS/SYSTEM 외 DBA 롤 보유자는 필요성 판단"),
    rule("D-05", "비밀번호 재사용에 대한 제약 설정", "중", ACC,
         [c("q", sq("SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_REUSE_MAX','PASSWORD_REUSE_TIME');"))],
         [{"when": {"q": {"regex": r"(?s)(?=.*PASSWORD_REUSE_MAX=UNLIMITED)(?=.*PASSWORD_REUSE_TIME=UNLIMITED)"}}, "then": "VULN"},
          {"when": {"q": {"regex": r"=\d+"}}, "then": "GOOD"}, {"else": "MANUAL"}]),
    rule("D-06", "DB 사용자 계정을 개별적으로 부여하여 사용", "중", ACC,
         [c("q", sq(f"SELECT username||':'||account_status FROM dba_users WHERE oracle_maintained='N' AND username NOT IN ({SYS_SCHEMAS}) ORDER BY 1;"))],
         [{"else": "MANUAL"}], manual=True, note="업무 계정 목록으로 1인 1계정 여부 판단"),
    rule("D-07", "root 권한으로 서비스 구동 제한", "중", ACC,
         [c("ps", "ps -eo user,comm 2>/dev/null | grep -E 'pmon|tnslsnr' | grep -v grep")],
         [{"when": {"ps": {"absent": True}}, "then": "MANUAL"}, {"when": {"ps": {"regex": r"(?m)^root\s"}}, "then": "VULN"},
          {"else": "GOOD"}], sqlrule=False, note="pmon/tnslsnr 이 root 로 떠 있으면 취약"),
    rule("D-08", "안전한 암호화 알고리즘 사용", "상", ACC,
         [c("q", sq("SELECT DISTINCT password_versions FROM dba_users WHERE account_status LIKE 'OPEN%' AND password_versions IS NOT NULL;"))],
         [{"when": {"q": {"regex": r"11G|12C"}}, "then": "GOOD"}, {"when": {"q": {"regex": r"10G"}}, "then": "VULN"},
          {"else": "MANUAL"}], note="password_versions 에 11G(SHA-1)/12C(SHA-512) 가 있으면 양호, 10G(DES)만이면 취약"),
    rule("D-09", "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정", "중", ACC,
         [c("q", sq("SELECT limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name='FAILED_LOGIN_ATTEMPTS';"))],
         [{"when": {"q": {"eq": "UNLIMITED"}}, "then": "VULN"}, {"when": {"q": {"le": 10}}, "then": "GOOD"},
          {"when": {"q": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}], note="기준: FAILED_LOGIN_ATTEMPTS 10 이하"),
    rule("D-10", "원격에서 DB 서버로의 접속 제한", "상", PERM,
         [c("sqlnet", "cat \"$ORACLE_HOME/network/admin/sqlnet.ora\" 2>/dev/null | grep -iv '^#'")],
         [{"when": {"sqlnet": {"regex": r"(?is)(?=.*tcp\.validnode_checking\s*=\s*yes)(?=.*tcp\.invited_nodes)"}}, "then": "GOOD"},
          {"else": "VULN"}], sqlrule=False, note="sqlnet.ora 에 TCP.VALIDNODE_CHECKING=yes 와 TCP.INVITED_NODES 가 있어야 양호"),
    rule("D-11", "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정", "상", PERM,
         [c("q", sq("SELECT value FROM v$parameter WHERE LOWER(name)='o7_dictionary_accessibility';")),
          c("pub", sq("SELECT count(*) FROM dba_tab_privs WHERE grantee='PUBLIC' AND owner='SYS' AND table_name LIKE 'DBA_%';"))],
         [{"when": {"q": {"regex": r"(?i)TRUE"}}, "then": "VULN"}, {"when": {"pub": {"gt": 0}}, "then": "VULN"},
          {"when": {"q": {"regex": r"(?i)FALSE"}}, "then": "GOOD"},
          {"when": {"q": {"absent": True}, "pub": {"eq": "0"}}, "then": "GOOD"}, {"else": "MANUAL"}],
         note="O7_DICTIONARY_ACCESSIBILITY 가 없는 버전(23ai+ 제거)은 FALSE 동작 — PUBLIC 의 DBA_ 뷰 권한 0 이면 양호"),
    rule("D-12", "안전한 리스너 비밀번호 설정 및 사용", "상", PERM,
         [c("lsn", "grep -i 'PASSWORDS_' \"$ORACLE_HOME/network/admin/listener.ora\" 2>/dev/null | sed 's/=.*/= <설정됨>/'"),
          c("ver", "export PATH=\"$ORACLE_HOME/bin:$PATH\"; sqlplus -v 2>&1 | grep -oE '[0-9]+\\.[0-9]+' | head -1")],
         [{"when": {"lsn": {"exists": True}}, "then": "GOOD"}, {"when": {"ver": {"ge": 12}}, "then": "NA"},
          {"when": {"ver": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}], sqlrule=False,
         note="12c 이상은 리스너 비밀번호가 폐기되고 로컬 OS 인증으로 대체 → 해당없음"),
    rule("D-13", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용", "중", PERM, [c("x", "true")],
         [{"else": "NA"}], sqlrule=False, note="Unix 호스트의 Oracle 에는 ODBC/OLE-DB 드라이버 개념이 없음. 클라이언트 PC 에서 확인"),
    rule("D-14", "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한 설정", "중", PERM,
         [c("w", "find -L \"$ORACLE_HOME/network/admin\" \"$ORACLE_HOME/dbs\" -type f \\( -name '*.ora' -o -name 'orapw*' \\) -perm -o+w 2>/dev/null"),
          c("ls", "ls -l \"$ORACLE_HOME/network/admin\"/*.ora \"$ORACLE_HOME/dbs\"/orapw* 2>/dev/null")],
         [{"when": {"ls": {"absent": True}}, "then": "MANUAL"}, {"when": {"w": {"exists": True}}, "then": "VULN"},
          {"else": "GOOD"}], sqlrule=False, note="*.ora·비밀번호 파일에 other 쓰기 권한이 있으면 취약"),
    rule("D-15", "관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한", "하", PERM,
         [c("lsn", "grep -i 'ADMIN_RESTRICTIONS' \"$ORACLE_HOME/network/admin/listener.ora\" 2>/dev/null")],
         [{"when": {"lsn": {"regex": r"(?i)=\s*ON"}}, "then": "GOOD"}, {"else": "VULN"}], sqlrule=False,
         note="listener.ora 에 ADMIN_RESTRICTIONS_<리스너>=ON"),
    rule("D-16", "Windows 인증 모드 사용", "하", PERM, [c("x", "true")], [{"else": "NA"}], sqlrule=False, note="MSSQL 전용 항목"),
    rule("D-17", "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한", "하", PERM,
         [c("q", sq("SELECT grantee||':'||privilege FROM dba_tab_privs WHERE table_name='AUD$' AND grantee NOT IN ('SYS','SYSTEM','DBA','AUDIT_ADMIN','AUDIT_VIEWER','SELECT_CATALOG_ROLE','DELETE_CATALOG_ROLE');"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "VULN"}]),
    rule("D-18", "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정", "상", PERM,
         [c("q", sq("SELECT granted_role FROM dba_role_privs WHERE grantee='PUBLIC';"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "VULN"}], note="PUBLIC 에 부여된 롤이 없어야 양호"),
    rule("D-19", "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정", "상", PERM,
         [c("q", sq("SELECT name||'='||value FROM v$parameter WHERE name IN ('os_roles','remote_os_authent','remote_os_roles');"))],
         [{"when": {"q": {"regex": r"(?i)=TRUE"}}, "then": "VULN"}, {"when": {"q": {"regex": r"(?i)=FALSE"}}, "then": "GOOD"},
          {"else": "MANUAL"}]),
    rule("D-20", "인가되지 않은 Object Owner의 제한", "하", PERM,
         [c("q", sq(f"SELECT DISTINCT owner FROM dba_objects WHERE owner<>'PUBLIC' AND owner NOT IN ({SYS_SCHEMAS}) AND owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y') ORDER BY 1;"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}], note="Oracle 관리 계정(oracle_maintained) 제외. 남는 소유자는 인가 여부 판단"),
    rule("D-21", "인가되지 않은 GRANT OPTION 사용 제한", "중", PERM,
         [c("q", sq("SELECT grantee||':'||owner||'.'||table_name FROM dba_tab_privs WHERE grantable='YES' AND grantee NOT IN ('SYS','SYSTEM') AND grantee NOT IN (SELECT role FROM dba_roles) AND owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y') AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y');"))],
         [{"when": {"q": {"absent": True}}, "then": "GOOD"}, {"else": "VULN"}], note="Oracle 관리 계정·객체 제외. 롤이 아닌 일반 계정에 WITH GRANT OPTION 이 있으면 취약(11g 는 oracle_maintained 없어 MANUAL)"),
    rule("D-22", "데이터베이스의 자원 제한 기능을 TRUE로 설정", "하", OPT,
         [c("q", sq("SELECT value FROM v$parameter WHERE name='resource_limit';"))],
         [{"when": {"q": {"regex": r"(?i)TRUE"}}, "then": "GOOD"}, {"when": {"q": {"regex": r"(?i)FALSE"}}, "then": "VULN"},
          {"else": "MANUAL"}]),
    rule("D-23", "xp_cmdshell 사용 제한", "상", OPT, [c("x", "true")], [{"else": "NA"}], sqlrule=False, note="MSSQL 전용 항목"),
    rule("D-24", "Registry Procedure 권한 제한", "상", OPT, [c("x", "true")], [{"else": "NA"}], sqlrule=False, note="MSSQL 전용 항목"),
    rule("D-25", "주기적 보안 패치 및 벤더 권고 사항 적용", "상", PATCH,
         [c("q", sq("SELECT banner_full FROM v$version WHERE rownum=1;")),
          c("patch", "export PATH=\"$ORACLE_HOME/bin:$PATH\"; \"$ORACLE_HOME/OPatch/opatch\" lspatches 2>&1 | head -20")],
         [{"else": "MANUAL"}], manual=True, note="버전·패치 목록을 Oracle Critical Patch Update 와 대조"),
    rule("D-26", "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정", "상", "로그관리",
         [c("q", sq("SELECT value FROM v$parameter WHERE name='audit_trail';")),
          c("uni", sq("SELECT count(*) FROM audit_unified_enabled_policies;"))],
         [{"when": {"q": {"regex": r"(?i)^NONE$"}, "uni": {"eq": "0"}}, "then": "VULN"},
          {"when": {"q": {"regex": r"(?i)DB|OS|XML"}}, "then": "GOOD"}, {"when": {"uni": {"gt": 0}}, "then": "GOOD"},
          {"else": "MANUAL"}], note="audit_trail 이 NONE 이고 통합감사 정책도 0개면 취약"),
]


def main(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in RULES:
        (out_dir / f"{r['id']}.yaml").write_text(
            f"# {r['id']} {r['name']} — Oracle 선언형 룰(SSH→sqlplus SELECT 전용, ORACLE_HOME/ORACLE_SID 파라미터 필요). 생성: scripts/gen_rules_oracle.py\n"
            + yaml.safe_dump(r, allow_unicode=True, sort_keys=False, width=300), encoding="utf-8", newline="\n")
    print(f"{len(RULES)} rules -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rulepacks/kisa-2026/rules")))
