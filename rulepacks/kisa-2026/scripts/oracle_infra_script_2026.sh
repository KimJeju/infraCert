#!/bin/ksh
#==============================================================================
# Oracle 19c 주요정보통신기반시설 취약점 점검 러너 (D-01 ~ D-26)
# 기준 : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드
#
# 구성 : (1) OS 레벨 점검 D-07/D-10/D-14/D-15 (sh)
#        (2) kisa_oracle_check.sql 호출 -> SQL 점검 16개 항목
#        (3) 결과 통합 + 양호/취약/수동/N-A 집계
#
# !! 읽기 전용 : ps/ls/grep 및 SELECT 만 수행, 설정 변경 없음 !!
#
# 사전 :
#   - oracle OS 계정(또는 ORACLE_HOME/ORACLE_SID 설정된 계정)으로 실행 권장
#   - sqlplus "/ as sysdba" 접속 가능해야 함 (또는 아래 DBCONN 변수 수정)
#
# 실행 : $ ./kisa_oracle_check.sh
#==============================================================================

LANG=C; export LANG

#------------------------ 환경 설정 (필요시 수정) -----------------------------
# ORACLE_HOME / ORACLE_SID 가 환경에 없으면 여기서 지정
: ${ORACLE_HOME:=""}          # 예: /u01/app/oracle/product/19.0.0/dbhome_1
: ${ORACLE_SID:=""}           # 예: ORCL
export ORACLE_HOME ORACLE_SID
[ -n "$ORACLE_HOME" ] && PATH=$ORACLE_HOME/bin:$PATH && export PATH

# DB 접속 방식 (기본: OS 인증 sysdba). 필요시 'user/pass@tns as sysdba' 등으로 변경
DBCONN='/ as sysdba'

# sqlnet.ora / listener.ora 경로 (미지정 시 자동 추정)
TNS_ADMIN_DIR="${TNS_ADMIN:-$ORACLE_HOME/network/admin}"
#-----------------------------------------------------------------------------

HOSTN=`hostname`
TODAY=`date +%Y%m%d_%H%M%S`
OUT="./kisa_oracle_result_${HOSTN}_${TODAY}.txt"
SQLF="./kisa_oracle_check.sql"

log() { echo "$*" | tee -a "$OUT"; }
# emit <CODE> <STATUS(양호|취약|수동|N/A)> <근거>   -> 표준 형식 출력(집계 대상)
emit() { log "$1 | $2 | $3"; }

> "$OUT"
log "########################################################################"
log "# Oracle 19c 기술적 취약점 점검 결과 (KISA D-01~D-26)"
log "# HOST       : $HOSTN"
log "# DATE       : `date`"
log "# ORACLE_HOME: ${ORACLE_HOME:-(미지정)}"
log "# ORACLE_SID : ${ORACLE_SID:-(미지정)}"
log "# TNS_ADMIN  : $TNS_ADMIN_DIR"
log "# (Read-Only 점검 / 설정 변경 없음)"
log "########################################################################"
log ""
log "===================================================================="
log "== [OS 레벨 점검 항목]"
log "===================================================================="

#==============================================================================
# D-07 (중) root 권한으로 서비스 구동 제한
#==============================================================================
PMON_OWNER=`ps -ef | grep -w 'ora_pmon_'"${ORACLE_SID}" | grep -v grep | awk '{print $1}' | head -1`
[ -z "$PMON_OWNER" ] && PMON_OWNER=`ps -ef | grep 'ora_pmon_' | grep -v grep | awk '{print $1}' | head -1`
LSNR_OWNER=`ps -ef | grep -w 'tnslsnr' | grep -v grep | awk '{print $1}' | head -1`
log ""
if [ -z "$PMON_OWNER" ] && [ -z "$LSNR_OWNER" ]; then
    emit D-07 수동 "Oracle 프로세스(pmon/tnslsnr) 미탐지 - 구동 여부 수동확인"
elif [ "$PMON_OWNER" = "root" ] || [ "$LSNR_OWNER" = "root" ]; then
    emit D-07 취약 "root 권한 구동: pmon=$PMON_OWNER tnslsnr=$LSNR_OWNER"
else
    emit D-07 양호 "비-root 구동: pmon=${PMON_OWNER:-NA} tnslsnr=${LSNR_OWNER:-NA}"
fi

#==============================================================================
# D-10 (상) 원격 DB 접속 제한 (sqlnet.ora tcp.validnode_checking)
#==============================================================================
SQLNET="$TNS_ADMIN_DIR/sqlnet.ora"
log ""
if [ -f "$SQLNET" ]; then
    VNC=`grep -i 'tcp.validnode_checking' "$SQLNET" | grep -v '^#' | grep -i 'yes'`
    INV=`grep -i 'tcp.invited_nodes' "$SQLNET" | grep -v '^#'`
    log "    >> $SQLNET"
    log "    >> `grep -i 'tcp.validnode_checking\|tcp.invited_nodes\|tcp.excluded_nodes' "$SQLNET" | grep -v '^#' | tr '\n' ' '`"
    if [ -n "$VNC" ] && [ -n "$INV" ]; then
        emit D-10 양호 "validnode_checking=yes 및 invited_nodes 설정됨"
    else
        emit D-10 취약 "접속 IP 제한 미설정(validnode_checking/invited_nodes 누락)"
    fi
else
    emit D-10 취약 "sqlnet.ora 미존재($SQLNET) - 접속제한 없음"
fi

#==============================================================================
# D-14 (중) 주요 설정/비밀번호 파일 권한 (일반사용자 쓰기권한 제거)
#   대상: listener.ora, sqlnet.ora, tnsnames.ora, orapw<SID>, spfile/init<SID>.ora
#==============================================================================
log ""
log "    >> 주요 파일 권한(소유자/권한 확인, 그룹·other 쓰기권한 없어야 양호):"
D14_BAD=0
for f in "$TNS_ADMIN_DIR/listener.ora" "$TNS_ADMIN_DIR/sqlnet.ora" \
         "$TNS_ADMIN_DIR/tnsnames.ora" \
         "$ORACLE_HOME/dbs/orapw${ORACLE_SID}" \
         "$ORACLE_HOME/dbs/spfile${ORACLE_SID}.ora" \
         "$ORACLE_HOME/dbs/init${ORACLE_SID}.ora"; do
    [ -f "$f" ] || continue
    line=`ls -l "$f"`
    log "    >> $line"
    # 권한 문자열에서 group(w)=6번째, other(w)=9번째 문자 확인
    perm=`echo "$line" | awk '{print $1}'`
    gw=`echo "$perm" | cut -c6`
    ow=`echo "$perm" | cut -c9`
    case "$f" in
        *orapw*|*spfile*|*init*) # 비번/파라미터 파일은 더 엄격(640 이하 권고)
            [ "$gw" = "w" -o "$ow" = "w" ] && D14_BAD=1 ;;
        *) # 네트워크 설정파일(644 이하 권고) : other 쓰기만 취약
            [ "$ow" = "w" ] && D14_BAD=1 ;;
    esac
done
if [ "$D14_BAD" = 1 ]; then
    emit D-14 취약 "일반사용자(group/other) 쓰기권한이 있는 주요파일 존재 (위 목록 확인)"
else
    emit D-14 양호 "주요 설정/비밀번호 파일에 과도한 쓰기권한 없음"
fi

#==============================================================================
# D-15 (하) 리스너 로그/trace 변경 제한 (ADMIN_RESTRICTIONS=ON + 디렉터리 권한)
#==============================================================================
LISTENER="$TNS_ADMIN_DIR/listener.ora"
log ""
if [ -f "$LISTENER" ]; then
    AR=`grep -i 'ADMIN_RESTRICTIONS' "$LISTENER" | grep -v '^#' | grep -i 'ON'`
    log "    >> $LISTENER : `grep -i 'ADMIN_RESTRICTIONS' "$LISTENER" | grep -v '^#' | tr '\n' ' '`"
    if [ -n "$AR" ]; then
        emit D-15 양호 "ADMIN_RESTRICTIONS_<listener>=ON 설정됨"
    else
        emit D-15 취약 "ADMIN_RESTRICTIONS 미설정(리스너로 파라미터 변경 가능)"
    fi
else
    emit D-15 수동 "listener.ora 미존재($LISTENER) - 리스너 사용여부 수동확인"
fi

#==============================================================================
# SQL 점검 항목 실행 (kisa_oracle_check.sql 호출)
#==============================================================================
log ""
if [ ! -f "$SQLF" ]; then
    log "[ERROR] $SQLF 파일이 없습니다. sh와 같은 디렉터리에 두세요."
else
    # sqlplus 존재 확인
    if command -v sqlplus >/dev/null 2>&1; then
        # SQL 스크립트가 결과를 $OUT 에 APPEND
        sqlplus -s -L "$DBCONN" @"$SQLF" "$OUT" </dev/null >/tmp/ora_sqlplus_$$.log 2>&1
        rc=$?
        if [ $rc -ne 0 ] || grep -qi 'ORA-01017\|ORA-12541\|ORA-12154\|TNS:\|ERROR' /tmp/ora_sqlplus_$$.log; then
            log ""
            log "[경고] sqlplus 실행 메시지:"
            cat /tmp/ora_sqlplus_$$.log | tee -a "$OUT"
        fi
        rm -f /tmp/ora_sqlplus_$$.log
    else
        log "[ERROR] sqlplus 명령을 찾을 수 없습니다. ORACLE_HOME/PATH 설정 후 재실행하세요."
    fi
fi

#==============================================================================
# 집계 요약
#==============================================================================
G=`grep -E '^D-[0-9]+ \| 양호 '   "$OUT" | wc -l | tr -d ' '`
V=`grep -E '^D-[0-9]+ \| 취약 '   "$OUT" | wc -l | tr -d ' '`
M=`grep -E '^D-[0-9]+ \| 수동 '   "$OUT" | wc -l | tr -d ' '`
N=`grep -E '^D-[0-9]+ \| N/A '    "$OUT" | wc -l | tr -d ' '`
T=`expr $G + $V + $M + $N`

log ""
log "########################################################################"
log "# 점검 요약 (Oracle D-01~D-26)"
log "#   [양호] : $G"
log "#   [취약] : $V"
log "#   [수동] : $M   (근거자료 수집됨, 운영자 판단 필요)"
log "#   [N/A]  : $N"
log "#   합계   : $T / 26"
log "#   결과파일: $OUT"
log "########################################################################"
log ""
log "[취약 항목 목록]"
grep -E '^D-[0-9]+ \| 취약 ' "$OUT" | tee -a /dev/null
