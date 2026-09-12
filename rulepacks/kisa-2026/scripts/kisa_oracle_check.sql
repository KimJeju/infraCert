--==============================================================================
-- Oracle 19c 주요정보통신기반시설 취약점 점검 SQL (D-* 중 SQL 점검 항목)
-- 기준 : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드
-- 실행 : sqlplus -s "/ as sysdba" @kisa_oracle_check.sql <결과파일>
--        (sh 러너 kisa_oracle_check.sh 에서 자동 호출됨)
-- !! 읽기 전용 : SELECT 만 수행, 설정 변경 없음 !!
-- 출력 형식 : D-XX | 양호|취약|수동 | 근거   (sh가 이 형식을 grep 하여 집계)
--==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 32767
SET PAGESIZE 0
SET LONG 20000
SET FEEDBACK OFF
SET HEADING OFF
SET TRIMSPOOL ON
SET VERIFY OFF
SET ECHO OFF
SET TERMOUT ON
WHENEVER SQLERROR CONTINUE
COLUMN result FORMAT A32000

SPOOL &1 APPEND

PROMPT ====================================================================
PROMPT == [SQL 점검 항목]  DBMS = Oracle 19c
PROMPT ====================================================================

-- ----------------------------------------------------------------------------
-- D-01 (상) 기본 계정의 비밀번호/정책 변경  : 비번값은 SQL로 확인 불가 -> 수동
-- ----------------------------------------------------------------------------
SELECT 'D-01 | 수동 | 기본계정 상태(초기비번 변경여부 수동확인): '||
  NVL(LISTAGG(username||'('||account_status||')', ', ' ON OVERFLOW TRUNCATE)
      WITHIN GROUP (ORDER BY username), '없음') AS result
FROM dba_users
WHERE username IN ('SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN','MDSYS','ORDSYS',
  'ORDPLUGINS','CTXSYS','XDB','WMSYS','APPQOSSYS','ANONYMOUS','AUDSYS','OJVMSYS',
  'DVSYS','LBACSYS','OLAPSYS','DIP','ORACLE_OCM','GSMADMIN_INTERNAL',
  'REMOTE_SCHEDULER_AGENT','SI_INFORMTN_SCHEMA');

-- ----------------------------------------------------------------------------
-- D-02 (상) 불필요(데모/샘플) 계정 제거
-- ----------------------------------------------------------------------------
SELECT 'D-02 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 데모/샘플 계정 없음'
  ELSE '취약 | 불필요계정 '||COUNT(*)||'건 존재(제거 권고): '||
       LISTAGG(username||'('||account_status||')', ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY username) END AS result
FROM dba_users
WHERE username IN ('SCOTT','HR','OE','SH','PM','IX','BI','DEMO','ADAMS','CLARK',
  'JONES','BLAKE','MILLER','SPATIAL_CSW_ADMIN_USR','SPATIAL_WFS_ADMIN_USR',
  'APEX_PUBLIC_USER','MDDATA','HR1','XS$NULL');

-- ----------------------------------------------------------------------------
-- D-03 (상) 비밀번호 사용기간/복잡도 (DEFAULT 프로파일 기준)
--   PASSWORD_LIFE_TIME=UNLIMITED 또는 PASSWORD_VERIFY_FUNCTION=NULL 이면 취약
-- ----------------------------------------------------------------------------
SELECT 'D-03 | '||CASE WHEN COUNT(*)=0 THEN '양호 | LIFE_TIME/VERIFY_FUNCTION 설정됨(DEFAULT)'
  ELSE '취약 | DEFAULT 프로파일 미흡: '||
       LISTAGG(resource_name||'='||limit, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY resource_name)||
       ' (커스텀 프로파일은 수동확인)' END AS result
FROM dba_profiles
WHERE profile='DEFAULT'
  AND ( (resource_name='PASSWORD_LIFE_TIME'      AND limit='UNLIMITED')
     OR (resource_name='PASSWORD_VERIFY_FUNCTION' AND limit='NULL') );

-- ----------------------------------------------------------------------------
-- D-04 (상) DBA(관리자) 권한 최소화 : admin_option=YES 비인가 부여 확인
-- ----------------------------------------------------------------------------
SELECT 'D-04 | '||CASE WHEN COUNT(*)=0 THEN '양호 | ADMIN OPTION 비인가 부여 없음'
  ELSE '취약 | ADMIN OPTION 부여 계정 '||COUNT(*)||'건: '||
       LISTAGG(grantee, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY grantee) END AS result
FROM ( SELECT DISTINCT grantee FROM dba_sys_privs
       WHERE admin_option='YES'
         AND grantee NOT IN ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','DATAPUMP_IMP_FULL_DATABASE',
             'IMP_FULL_DATABASE','EXP_FULL_DATABASE','SCHEDULER_ADMIN','GSMADMIN_INTERNAL','BACSYS')
         AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
          -- Oracle 제공 계정/롤(DV_ACCTMGR, GSMUSER_ROLE, OGG_*, SYSKM ...)은 제외 — 네이티브 D-04 와 동일 보정(2026-09-12)
          AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y')
          AND grantee NOT IN (SELECT role FROM dba_roles WHERE oracle_maintained='Y') );

-- ----------------------------------------------------------------------------
-- D-05 (중) 비밀번호 재사용 제약 (DEFAULT 프로파일)
-- ----------------------------------------------------------------------------
SELECT 'D-05 | '||CASE WHEN COUNT(*)=0 THEN '양호 | REUSE_MAX/REUSE_TIME 제한 설정됨'
  ELSE '취약 | 재사용제한 미설정: '||
       LISTAGG(resource_name||'='||limit, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY resource_name) END AS result
FROM dba_profiles
WHERE profile='DEFAULT'
  AND resource_name IN ('PASSWORD_REUSE_MAX','PASSWORD_REUSE_TIME')
  AND limit IN ('UNLIMITED','DEFAULT');

-- ----------------------------------------------------------------------------
-- D-06 (중) 사용자 계정 개별 부여 : 공용계정 여부는 수동확인 (계정목록 제공)
-- ----------------------------------------------------------------------------
SELECT 'D-06 | 수동 | 비시스템 계정 목록(공용계정 사용여부 수동확인): '||
  NVL(LISTAGG(username, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY username),'없음') AS result
FROM dba_users
WHERE oracle_maintained='N';

-- ----------------------------------------------------------------------------
-- D-08 (상) 안전한 암호화 알고리즘 (SHA-2 이상; password_versions 에 12C 포함)
-- ----------------------------------------------------------------------------
SELECT 'D-08 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 모든 계정 12C(SHA-512) 해시 사용'
  ELSE '취약 | SHA-256미만(10G/11G) 계정 '||COUNT(*)||'건: '||
       LISTAGG(username||'('||password_versions||')', ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY username) END AS result
FROM dba_users
WHERE password_versions IS NOT NULL
  AND password_versions NOT LIKE '%12C%'
  AND authentication_type='PASSWORD';

-- ----------------------------------------------------------------------------
-- D-09 (중) 로그인 실패 잠금 (DEFAULT 프로파일 FAILED_LOGIN_ATTEMPTS)
-- ----------------------------------------------------------------------------
SELECT 'D-09 | '||CASE WHEN COUNT(*)=0 THEN '양호 | FAILED_LOGIN_ATTEMPTS 제한 설정됨'
  ELSE '취약 | FAILED_LOGIN_ATTEMPTS=UNLIMITED (DEFAULT)' END AS result
FROM dba_profiles
WHERE profile='DEFAULT' AND resource_name='FAILED_LOGIN_ATTEMPTS' AND limit='UNLIMITED';

-- ----------------------------------------------------------------------------
-- D-11 (상) 시스템 테이블 비인가 접근 제한 (가이드 쿼리)
-- ----------------------------------------------------------------------------
SELECT 'D-11 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 시스템테이블 DBA外 접근 없음'
  ELSE '취약 | 비인가 접근 '||COUNT(*)||'건: '||
       LISTAGG(grantee, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY grantee) END AS result
FROM ( SELECT DISTINCT grantee FROM dba_tab_privs
  WHERE (owner='SYS' OR table_name LIKE 'DBA_%') AND privilege<>'EXECUTE'
    AND grantee NOT IN ('PUBLIC','AQ_ADMINISTRATOR_ROLE','AQ_USER_ROLE','CTXSYS','DBA',
      'DELETE_CATALOG_ROLE','EXECUTE_CATALOG_ROLE','EXP_FULL_DATABASE','GATHER_SYSTEM_STATISTICS',
      'HS_ADMIN_ROLE','IMP_FULL_DATABASE','LOGSTDBY_ADMINISTRATOR','MDSYS','OEM_MONITOR','OLAPSYS',
      'ORDSYS','OUTLN','RECOVERY_CATALOG_OWNER','SELECT_CATALOG_ROLE','SYSTEM','WKSYS','WMSYS',
      'WM_ADMIN_ROLE','XDB','LBACSYS','XDBADMIN','SYS','AUDSYS','GSMADMIN_INTERNAL','DV_SECANALYST')
    AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') );

-- ----------------------------------------------------------------------------
-- D-17 (하) Audit Table(AUD$) 접근 제한
-- ----------------------------------------------------------------------------
SELECT 'D-17 | '||CASE WHEN COUNT(*)=0 THEN '양호 | AUD$ 비인가 접근권한 없음'
  ELSE '취약 | AUD$ 비인가 접근 '||COUNT(*)||'건: '||
       LISTAGG(grantee, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY grantee) END AS result
FROM dba_tab_privs
WHERE table_name='AUD$'
  AND grantee NOT IN ('SYS','SYSTEM','DBA','DELETE_CATALOG_ROLE','SELECT_CATALOG_ROLE','AUDSYS','DV_SECANALYST');

-- ----------------------------------------------------------------------------
-- D-18 (상) DBA Role 이 PUBLIC 에 부여되지 않을 것
-- ----------------------------------------------------------------------------
SELECT 'D-18 | '||CASE WHEN COUNT(*)=0 THEN '양호 | PUBLIC 에 Role 부여 없음'
  ELSE '취약 | PUBLIC 부여 Role '||COUNT(*)||'건: '||
       LISTAGG(granted_role, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY granted_role) END AS result
FROM dba_role_privs
WHERE grantee='PUBLIC';

-- ----------------------------------------------------------------------------
-- D-19 (상) OS_ROLES / REMOTE_OS_AUTHENT / REMOTE_OS_ROLES = FALSE
-- ----------------------------------------------------------------------------
SELECT 'D-19 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 3개 파라미터 모두 FALSE'
  ELSE '취약 | TRUE 설정: '||
       LISTAGG(name||'='||value, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY name) END AS result
FROM v$parameter
WHERE name IN ('os_roles','remote_os_authent','remote_os_roles')
  AND UPPER(value)<>'FALSE';

-- ----------------------------------------------------------------------------
-- D-20 (하) 인가되지 않은 Object Owner 제한 (가이드 쿼리)
-- ----------------------------------------------------------------------------
SELECT 'D-20 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 비인가 Object Owner 없음'
  ELSE '수동 | 일반계정 Object Owner '||COUNT(*)||'건(용도 확인): '||
       LISTAGG(owner, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY owner) END AS result
FROM ( SELECT DISTINCT owner FROM dba_objects
  WHERE owner NOT IN ('SYS','SYSTEM','MDSYS','CTXSYS','ORDSYS','ORDPLUGINS','OLAPSYS',
    'OUTLN','LBACSYS','DBSNMP','WMSYS','XDB','APPQOSSYS','AUDSYS','GSMADMIN_INTERNAL',
    'OJVMSYS','DVSYS','ORDDATA','SI_INFORMTN_SCHEMA','DV_SECANALYST','PUBLIC','REMOTE_SCHEDULER_AGENT')
    AND owner NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA')
    AND owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y') );

-- ----------------------------------------------------------------------------
-- D-21 (중) 인가되지 않은 GRANT OPTION 제한 (가이드 쿼리)
-- ----------------------------------------------------------------------------
SELECT 'D-21 | '||CASE WHEN COUNT(*)=0 THEN '양호 | 비인가 WITH GRANT OPTION 없음'
  ELSE '취약 | GRANT OPTION 부여 '||COUNT(*)||'건: '||
       LISTAGG(grantee||':'||owner||'.'||table_name, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY grantee) END AS result
FROM dba_tab_privs
WHERE grantable='YES'
  AND owner NOT IN ('SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM','WMSYS','LBACSYS','CTXSYS','XDB','AUDSYS')
  AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA');

-- ----------------------------------------------------------------------------
-- D-22 (하) RESOURCE_LIMIT = TRUE
-- ----------------------------------------------------------------------------
SELECT 'D-22 | '||CASE WHEN UPPER(value)='TRUE' THEN '양호 | RESOURCE_LIMIT=TRUE'
  ELSE '취약 | RESOURCE_LIMIT='||value END AS result
FROM v$parameter WHERE name='resource_limit';

-- ----------------------------------------------------------------------------
-- D-25 (상) 보안 패치/버전 : 버전 출력 (최신 패치 적용여부 수동확인)
-- ----------------------------------------------------------------------------
SELECT 'D-25 | 수동 | 버전 확인(최신 PSU/RU 적용여부 수동확인): '||banner AS result
FROM v$version WHERE banner LIKE 'Oracle%' AND ROWNUM=1;

-- ----------------------------------------------------------------------------
-- D-26 (상) 감사 기록 설정 (audit_trail / Unified Auditing)
-- ----------------------------------------------------------------------------
SELECT 'D-26 | '||
  CASE WHEN UPPER(p.value)<>'NONE' THEN '양호 | audit_trail='||p.value
       WHEN u.cnt>0 THEN '양호 | Unified Auditing 정책 '||u.cnt||'건 활성'
       ELSE '취약 | audit_trail=NONE 이고 Unified 감사정책 없음' END AS result
FROM (SELECT value FROM v$parameter WHERE name='audit_trail') p,
     (SELECT COUNT(*) cnt FROM audit_unified_enabled_policies) u;

PROMPT ====================================================================
PROMPT == [N/A 항목]  Oracle 19c 미해당
PROMPT D-12 | N/A | 리스너 비밀번호 - Oracle 12cR2 이후 미지원
PROMPT D-13 | N/A | ODBC/OLE-DB - Windows OS 항목
PROMPT D-16 | N/A | Windows 인증 모드 - MSSQL 항목
PROMPT D-23 | N/A | xp_cmdshell - MSSQL 항목
PROMPT D-24 | N/A | Registry Procedure - MSSQL 항목
PROMPT ====================================================================

SPOOL OFF
EXIT
