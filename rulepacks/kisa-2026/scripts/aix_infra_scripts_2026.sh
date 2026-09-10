#!/bin/ksh
#==============================================================================
# AIX 주요정보통신기반시설 기술적 취약점 점검 스크립트 (U-01 ~ U-67)
# 기준 : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드
# 대상 : AIX (7.x / 9.x), PowerVM VIOS(oem_setup_env 진입 후 동일 사용 가능)
#
# !! 읽기 전용(Read-Only) !! - 이 스크립트는 설정을 변경하지 않습니다.
#   조치는 절대 자동 수행하지 않으며, 현재 상태만 점검/판정합니다.
#
# 실행 : # ./aix_kisa_check.sh            (root 권장)
#        결과파일 : ./aix_kisa_result_<hostname>_<date>.txt
#
# 판정 표기 : [양호] GOOD / [취약] VULN / [수동] MANUAL / [N/A] 해당없음
#   - MANUAL : 자동판정이 부적절하거나 운영정책 판단이 필요한 항목 (근거자료만 수집)
#==============================================================================

LANG=C; export LANG
PATH=/usr/bin:/usr/sbin:/etc:/sbin:$PATH; export PATH

HOSTN=`hostname`
TODAY=`date +%Y%m%d_%H%M%S`
OUT="./aix_kisa_result_${HOSTN}_${TODAY}.txt"

CNT_GOOD=0; CNT_VULN=0; CNT_MANUAL=0; CNT_NA=0

#------------------------------------------------------------------------------
# 출력 헬퍼
#------------------------------------------------------------------------------
log() { echo "$*" | tee -a "$OUT"; }

# result <CODE> <중요도> <항목명> <STATUS>
#   STATUS = GOOD|VULN|MANUAL|NA
result() {
    _code="$1"; _sev="$2"; _name="$3"; _st="$4"
    case "$_st" in
        GOOD)   _tag="[양호]  "; CNT_GOOD=`expr $CNT_GOOD + 1` ;;
        VULN)   _tag="[취약]  "; CNT_VULN=`expr $CNT_VULN + 1` ;;
        MANUAL) _tag="[수동]  "; CNT_MANUAL=`expr $CNT_MANUAL + 1` ;;
        NA)     _tag="[N/A]   "; CNT_NA=`expr $CNT_NA + 1` ;;
    esac
    log ""
    log "------------------------------------------------------------------------"
    log "${_tag}${_code}(${_sev})  ${_name}"
}
detail() { log "    >> $*"; }   # 판단 근거/수집값 출력

# 숫자 여부 검사 (빈값/비숫자 -> false). 빈값+숫자비교 깨짐 방지용
is_num() { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }

# 무거운 전체 파일시스템 스캔(find /) 수행 여부. HEAVY=0 으로 건너뛰기 가능
HEAVY=${HEAVY:-1}

header() {
    log "########################################################################"
    log "# AIX 기술적 취약점 점검 결과 (KISA 주요정보통신기반시설 가이드 U-01~U-67)"
    log "# HOST   : $HOSTN"
    log "# DATE   : `date`"
    log "# OSLEVEL: `oslevel -s 2>/dev/null`"
    log "# UNAME  : `uname -a`"
    log "# (Read-Only 점검 / 설정 변경 없음)"
    log "########################################################################"
}

#==============================================================================
# 1. 계정 관리 (U-01 ~ U-13)
#==============================================================================

u01() { # root 계정 원격 접속 제한 (상)
    st=GOOD
    rl=`lssec -f /etc/security/user -s root -a rlogin 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    detail "/etc/security/user root rlogin = ${rl:-(미설정)}  (false=양호)"
    [ "$rl" = "true" ] && st=VULN
    if [ -f /etc/ssh/sshd_config ]; then
        prl=`grep -i '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config | tail -1`
        detail "sshd_config: ${prl:-(미설정=OpenSSH 기본 prohibit-password)}"
        # PermitRootLogin yes -> 명백히 취약. 빈값(기본값)은 확인필요지만 기존 VULN은 격하 금지
        if echo "$prl" | grep -iq '[[:space:]]yes'; then st=VULN
        elif [ -z "$prl" ] && [ "$st" != VULN ]; then st=MANUAL
        fi
    fi
    result U-01 상 "root 계정 원격 접속 제한" $st
}

u02() { # 비밀번호 관리정책 설정 (상)
    st=GOOD
    minlen=`lssec -f /etc/security/user -s default -a minlen 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    maxage=`lssec -f /etc/security/user -s default -a maxage 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    minage=`lssec -f /etc/security/user -s default -a minage 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    minalpha=`lssec -f /etc/security/user -s default -a minalpha 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    minother=`lssec -f /etc/security/user -s default -a minother 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    histsize=`lssec -f /etc/security/user -s default -a histsize 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    detail "minlen=$minlen maxage(주)=$maxage minage(주)=$minage minalpha=$minalpha minother=$minother histsize=$histsize"
    detail "권고: minlen>=8, maxage<=13(약90일), minage>=1, minalpha+minother>=조합, histsize>=4"
    # 미설정(빈값) 또는 기준 미달이면 취약 (빈값+숫자비교 깨짐 방지 위해 is_num 선검사)
    if ! is_num "$minlen" || [ "$minlen" -lt 8 ]; then st=VULN; detail "-> minlen 미설정/8미만 취약"; fi
    if ! is_num "$maxage" || [ "$maxage" -eq 0 ]; then st=VULN; detail "-> maxage 미설정/0(무제한) 취약"; fi
    result U-02 상 "비밀번호 관리정책 설정" $st
}

u03() { # 계정 잠금 임계값 설정 (상)
    st=GOOD
    lr=`lssec -f /etc/security/user -s default -a loginretries 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    detail "/etc/security/user default loginretries = ${lr:-(미설정)}  (1~10 양호, 0/미설정 취약)"
    if [ -z "$lr" ]; then st=VULN
    elif [ "$lr" -le 0 -o "$lr" -gt 10 ] 2>/dev/null; then st=VULN
    fi
    result U-03 상 "계정 잠금 임계값 설정" $st
}

u04() { # 비밀번호 파일 보호 (상) - AIX는 /etc/security/passwd에 암호화 저장
    st=GOOD
    if [ -f /etc/security/passwd ]; then
        detail "/etc/security/passwd 존재 (AIX는 기본적으로 암호화 저장)"
        # /etc/passwd 2번째 필드가 ! 또는 * 인지 확인
        bad=`awk -F: '($2!="!" && $2!="*" && $2!="" && $2!="x") {print $1}' /etc/passwd 2>/dev/null`
        if [ -n "$bad" ]; then detail "passwd 2필드 비정상 계정: $bad"; st=MANUAL; fi
    else
        detail "/etc/security/passwd 미존재"; st=VULN
    fi
    result U-04 상 "비밀번호 파일 보호" $st
}

u05() { # root 이외 UID 0 금지 (상)
    st=GOOD
    uid0=`awk -F: '($3==0){print $1}' /etc/passwd`
    detail "UID=0 계정 목록: $uid0"
    cnt=`echo "$uid0" | grep -vw root | grep -v '^$' | wc -l | tr -d ' '`
    [ "$cnt" -gt 0 ] && st=VULN
    result U-05 상 "root 이외의 UID 0 금지" $st
}

u06() { # 사용자 계정 su 기능 제한 (상)
    st=MANUAL
    perm=`ls -l /usr/bin/su 2>/dev/null`
    grp=`grep -i '^sugroup\|^system\|^wheel' /etc/group 2>/dev/null`
    detail "ls -l /usr/bin/su : $perm"
    detail "su 허용그룹 후보(/etc/group): ${grp:-(없음)}"
    detail "판단: su가 4750 + 특정그룹(sugroup 등)으로 제한되어야 양호 / 4755(전체사용 가능)면 취약"
    echo "$perm" | grep -q 'rwsr-x---' && st=GOOD
    echo "$perm" | grep -q 'rwsr-xr-x' && st=VULN
    result U-06 상 "사용자 계정 su 기능 제한" $st
}

u07() { # 불필요한 계정 제거 (하)
    st=MANUAL
    detail "기본 점검 대상(미사용 시 제거): lp, uucp, nuucp, guest, daemon, bin, sys, adm, imnadm 등"
    detail "현재 계정 목록:"; lsuser -a id ALL 2>/dev/null | tee -a "$OUT"
    detail "판단: 운영상 불필요한 기본/게스트 계정 존재 여부를 운영자와 확인 필요"
    result U-07 하 "불필요한 계정 제거" $st
}

u08() { # 관리자 그룹에 최소한의 계정 (중)
    st=MANUAL
    sysg=`grep -i '^system:' /etc/group`
    detail "system 그룹(GID 0) 구성원: $sysg"
    detail "판단: 관리자 그룹에 불필요한 계정 미포함 여부 확인 필요"
    result U-08 중 "관리자 그룹에 최소한의 계정 포함" $st
}

u09() { # 계정이 존재하지 않는 GID 금지 (하)
    st=GOOD
    grps=`awk -F: '{print $4}' /etc/passwd | sort -u`
    bad=""
    for g in $grps; do
        grep -q ":$g:" /etc/group || bad="$bad $g"
    done
    detail "passwd에서 사용 중이나 group에 없는 GID:${bad:- (없음)}"
    [ -n "$bad" ] && st=VULN
    result U-09 하 "계정이 존재하지 않는 GID 금지" $st
}

u10() { # 동일한 UID 금지 (중)
    st=GOOD
    dup=`awk -F: '{print $3}' /etc/passwd | sort | uniq -d`
    detail "중복 UID:${dup:- (없음)}"
    [ -n "$dup" ] && st=VULN
    result U-10 중 "동일한 UID 금지" $st
}

u11() { # 사용자 Shell 점검 (하)
    st=MANUAL
    detail "로그인 불필요 계정에 /bin/false, /usr/bin/false, /dev/null 등 부여 여부 확인"
    awk -F: '($7 !~ /false|nologin|null|sysadmin/){print "  "$1" -> "$7}' /etc/passwd | tee -a "$OUT"
    result U-11 하 "사용자 Shell 점검" $st
}

u12() { # 세션 종료 시간 설정 (하)
    st=GOOD
    tmout=`grep -i 'TMOUT' /etc/profile /etc/security/.profile 2>/dev/null`
    detail "TMOUT 설정: ${tmout:-(미설정)}  (600초 이하 권고)"
    [ -z "$tmout" ] && st=VULN
    result U-12 하 "세션 종료 시간 설정" $st
}

u13() { # 안전한 비밀번호 암호화 알고리즘 사용 (중)
    st=GOOD
    alg=`lssec -f /etc/security/login.cfg -s usw -a pwd_algorithm 2>/dev/null | awk -F= '{print $2}' | tr -d ' '`
    detail "pwd_algorithm = ${alg:-crypt(기본 DES)}  (ssha256/ssha512 권고, crypt=취약)"
    case "$alg" in
        ssha256|ssha512|sha256|sha512) st=GOOD ;;
        ""|crypt) st=VULN ;;
        *) st=MANUAL ;;
    esac
    result U-13 중 "안전한 비밀번호 암호화 알고리즘 사용" $st
}

#==============================================================================
# 2. 파일 및 디렉터리 관리 (U-14 ~ U-33)
#==============================================================================

u14() { # root 홈, 패스 디렉터리 권한 및 PATH 설정 (상)
    st=GOOD
    pathenv=`su - root -c 'echo $PATH' 2>/dev/null`
    detail "root PATH = ${pathenv:-(확인불가)}"
    echo "$pathenv" | grep -Eq '(^|:)\.(:|$)|::' && { st=VULN; detail "PATH에 '.' 또는 '::' 포함 -> 취약"; }
    result U-14 상 "root 홈, 패스 디렉터리 권한 및 PATH 설정" $st
}

u15() { # 파일 및 디렉터리 소유자 설정 (상)
    st=GOOD
    if [ "$HEAVY" != 1 ]; then detail "(HEAVY=0: 전체스캔 생략)"; st=MANUAL; result U-15 상 "파일 및 디렉터리 소유자 설정" $st; return; fi
    no=`find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -50`
    detail "소유자/그룹 없는 파일(최대50):"; [ -n "$no" ] && echo "$no" | tee -a "$OUT"
    [ -n "$no" ] && st=VULN
    result U-15 상 "파일 및 디렉터리 소유자 설정" $st
}

# 공통 파일 권한 점검 (소유자 root, 권한 max 이하)
chk_file() {
    _code="$1"; _sev="$2"; _name="$3"; _file="$4"; _maxoct="$5"
    st=GOOD
    if [ ! -e "$_file" ]; then
        detail "$_file 미존재"; result "$_code" "$_sev" "$_name" GOOD; return
    fi
    own=`ls -l "$_file" | awk '{print $3}'`
    perm=`ls -l "$_file"`
    oct=`istat "$_file" 2>/dev/null | grep -i 'Mode' | sed 's/.*0\([0-7][0-7][0-7]\).*/\1/'`
    detail "$perm"
    detail "owner=$own  (기대: root, 권한 <= $_maxoct)"
    [ "$own" != "root" ] && st=VULN
    result "$_code" "$_sev" "$_name" $st
}

u16() { chk_file U-16 상 "/etc/passwd 파일 소유자 및 권한 설정(644 이하)" /etc/passwd 644; }
u17() { # 시스템 시작 스크립트 권한 (상)
    st=MANUAL
    detail "AIX 시작 스크립트: /etc/rc.*, /etc/inittab, /etc/rc.tcpip 등"
    ls -l /etc/rc.tcpip /etc/inittab /etc/rc.nfs 2>/dev/null | tee -a "$OUT"
    detail "판단: 소유자 root, 일반사용자 쓰기권한 없어야 양호"
    result U-17 상 "시스템 시작 스크립트 권한 설정" $st
}
u18() { chk_file U-18 상 "/etc/security/passwd 소유자 및 권한(400 이하)" /etc/security/passwd 400; }
u19() { chk_file U-19 상 "/etc/hosts 소유자 및 권한(644 이하)" /etc/hosts 644; }
u20() { chk_file U-20 상 "/etc/inetd.conf 소유자 및 권한(600 이하)" /etc/inetd.conf 600; }
u21() { chk_file U-21 상 "/etc/syslog.conf 소유자 및 권한(644 이하)" /etc/syslog.conf 644; }
u22() { chk_file U-22 상 "/etc/services 소유자 및 권한(644 이하)" /etc/services 644; }

u23() { # SUID, SGID, Sticky bit 설정 파일 점검 (상)
    st=MANUAL
    if [ "$HEAVY" != 1 ]; then detail "(HEAVY=0: 전체스캔 생략)"; result U-23 상 "SUID, SGID, Sticky bit 설정 파일 점검" $st; return; fi
    detail "SUID/SGID 설정 파일 목록(불필요한 항목 제거 대상). 시간이 다소 소요됩니다..."
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -200 | tee -a "$OUT"
    detail "판단: 위 목록 중 불필요/취약(예: /usr/bin/at, rdist 등) 항목 제거 여부 확인"
    result U-23 상 "SUID, SGID, Sticky bit 설정 파일 점검" $st
}

u24() { # 사용자/시스템 환경변수 파일 소유자 및 권한 (상)
    st=MANUAL
    detail "환경변수 파일: /etc/profile, /etc/environment, \$HOME/.profile, .kshrc 등"
    ls -l /etc/profile /etc/environment 2>/dev/null | tee -a "$OUT"
    detail "판단: 소유자 root/해당계정, 타사용자 쓰기권한 없어야 양호"
    result U-24 상 "사용자, 시스템 환경변수 파일 소유자 및 권한 설정" $st
}

u25() { # world writable 파일 점검 (상)
    st=GOOD
    if [ "$HEAVY" != 1 ]; then detail "(HEAVY=0: 전체스캔 생략)"; st=MANUAL; result U-25 상 "world writable 파일 점검" $st; return; fi
    ww=`find / -xdev -type f -perm -2 ! -type l 2>/dev/null | head -100`
    detail "World-writable 파일(최대100):"; [ -n "$ww" ] && echo "$ww" | tee -a "$OUT"
    [ -n "$ww" ] && st=VULN
    result U-25 상 "world writable 파일 점검" $st
}

u26() { # /dev에 존재하지 않는 device 파일 (상)
    st=GOOD
    nd=`find /dev -type f -exec ls -l {} \; 2>/dev/null | head -50`
    detail "/dev 내 일반파일(device 아님, 점검대상):"; [ -n "$nd" ] && echo "$nd" | tee -a "$OUT"
    [ -n "$nd" ] && st=MANUAL
    result U-26 상 "/dev에 존재하지 않는 device 파일 점검" $st
}

u27() { # .rhosts, hosts.equiv 사용 금지 (상)
    st=GOOD
    if [ -f /etc/hosts.equiv ]; then
        detail "/etc/hosts.equiv 존재: `ls -l /etc/hosts.equiv`"
        grep -q '+' /etc/hosts.equiv && { st=VULN; detail "hosts.equiv에 '+' 존재 -> 취약"; }
    else detail "/etc/hosts.equiv 미존재 (양호)"; fi
    for h in `awk -F: '{print $6}' /etc/passwd | sort -u`; do
        if [ -f "$h/.rhosts" ]; then
            detail "$h/.rhosts 존재: `ls -l $h/.rhosts`"
            grep -q '+' "$h/.rhosts" 2>/dev/null && { st=VULN; detail "$h/.rhosts에 '+' 존재 -> 취약"; }
        fi
    done
    result U-27 상 "\$HOME/.rhosts, hosts.equiv 사용 금지" $st
}

u28() { # 접속 IP 및 포트 제한 (상)
    st=MANUAL
    detail "TCP Wrapper/방화벽 설정 확인"
    ls -l /etc/hosts.allow /etc/hosts.deny 2>/dev/null | tee -a "$OUT"
    [ -f /etc/hosts.allow ] && { detail "hosts.allow:"; grep -v '^#' /etc/hosts.allow | tee -a "$OUT"; }
    detail "판단: 허용 IP/포트 제한 정책 적용 여부 확인 (미설정 시 취약)"
    [ ! -f /etc/hosts.allow -a ! -f /etc/hosts.deny ] && { st=VULN; detail "접근제어 미설정 -> 취약"; }
    result U-28 상 "접속 IP 및 포트 제한" $st
}

u29() { chk_file U-29 하 "/etc/hosts.lpd 소유자 및 권한(600 이하/미존재 양호)" /etc/hosts.lpd 600; }

u30() { # UMASK 설정 관리 (중)
    st=VULN
    um=`grep -i 'umask' /etc/security/user /etc/profile 2>/dev/null | grep -v '^#'`
    detail "UMASK 설정: ${um:-(미설정)}  (022 이상 양호)"
    echo "$um" | grep -Eq '022|027|077' && st=GOOD
    result U-30 중 "UMASK 설정 관리" $st
}

u31() { # 홈 디렉토리 소유자 및 권한 (중)
    st=GOOD
    while IFS=: read u x uid gid gc home sh; do
        [ "$uid" -ge 200 ] 2>/dev/null || continue
        [ -d "$home" ] || continue
        ho=`ls -ald "$home" | awk '{print $3}'`
        hp=`ls -ald "$home" | awk '{print $1}'`
        if [ "$ho" != "$u" ] || echo "$hp" | grep -q '.......w.'; then
            detail "$u home=$home owner=$ho perm=$hp -> 점검대상"; st=VULN
        fi
    done < /etc/passwd
    [ "$st" = GOOD ] && detail "일반계정 홈 디렉토리 소유자/권한 양호"
    result U-31 중 "홈 디렉토리 소유자 및 권한 설정" $st
}

u32() { # 홈 디렉토리 존재 관리 (중)
    st=GOOD
    while IFS=: read u x uid gid gc home sh; do
        [ "$uid" -ge 200 ] 2>/dev/null || continue
        case "$sh" in *false|*nologin|*null) continue;; esac
        if [ ! -d "$home" ]; then detail "$u 홈디렉토리 없음: $home -> 취약"; st=VULN; fi
    done < /etc/passwd
    [ "$st" = GOOD ] && detail "홈 디렉토리 미존재 계정 없음"
    result U-32 중 "홈 디렉토리로 지정한 디렉토리의 존재 관리" $st
}

u33() { # 숨겨진 파일 및 디렉토리 (하)
    st=MANUAL
    if [ "$HEAVY" != 1 ]; then detail "(HEAVY=0: 전체스캔 생략)"; result U-33 하 "숨겨진 파일 및 디렉토리 검색 및 제거" $st; return; fi
    detail "숨겨진 파일/디렉토리 점검(의심파일 수동확인). 샘플(최대50):"
    find / -xdev -name '.*' \( -type f -o -type d \) 2>/dev/null | grep -Ev '/\.$|/\.\.$' | head -50 | tee -a "$OUT"
    result U-33 하 "숨겨진 파일 및 디렉토리 검색 및 제거" $st
}

#==============================================================================
# 3. 서비스 관리 (U-34 ~ U-63)
#==============================================================================

# inetd.conf 서비스 활성화 점검 헬퍼 (주석처리 안돼있으면 활성)
inetd_active() {
    [ -f /etc/inetd.conf ] || { echo NOFILE; return; }
    if grep -E "^[[:space:]]*$1([[:space:]]|$)" /etc/inetd.conf >/dev/null 2>&1; then
        echo ACTIVE
    else
        echo INACTIVE
    fi
}

chk_inetd() {
    _code="$1"; _sev="$2"; _name="$3"; shift 3
    st=GOOD; found=""
    for svc in "$@"; do
        r=`inetd_active "$svc"`
        [ "$r" = ACTIVE ] && { found="$found $svc"; st=VULN; }
    done
    if [ -n "$found" ]; then detail "활성화된 서비스(취약):$found"
    else detail "대상 서비스 모두 비활성화(양호): $*"; fi
    result "$_code" "$_sev" "$_name" $st
}

u34() { chk_inetd U-34 상 "Finger 서비스 비활성화" finger; }
u35() { # 공유 서비스 익명 접근 제한 (상) - NFS/SMB 익명 공유
    st=MANUAL
    detail "/etc/exports (NFS) 및 익명 공유 설정 확인"
    [ -f /etc/exports ] && cat /etc/exports | tee -a "$OUT" || detail "/etc/exports 미존재"
    result U-35 상 "공유 서비스에 대한 익명 접근 제한 설정" $st
}
u36() { chk_inetd U-36 상 "r 계열 서비스 비활성화(rlogin/rsh/rexec)" shell login exec rlogind rshd rexecd; }

u37() { # crontab 설정파일 권한 (상)
    st=GOOD
    detail "cron 디렉토리/파일 권한:"
    ls -ld /var/spool/cron/crontabs 2>/dev/null | tee -a "$OUT"
    ls -l /var/spool/cron/crontabs 2>/dev/null | head -20 | tee -a "$OUT"
    ls -l /var/adm/cron/cron.allow /var/adm/cron/cron.deny 2>/dev/null | tee -a "$OUT"
    detail "판단: crontab 파일 640 이하, 소유자 root/적정 여부 확인 (과도 권한 시 취약)"
    bad=`find /var/spool/cron/crontabs -type f -perm -022 2>/dev/null`
    [ -n "$bad" ] && { st=VULN; detail "타사용자 쓰기가능 crontab: $bad"; }
    result U-37 상 "crontab 설정파일 권한 설정" $st
}

u38() { chk_inetd U-38 상 "DoS 취약 서비스 비활성화(echo/discard/daytime/chargen)" echo discard daytime chargen; }

u39() { # 불필요한 NFS 서비스 비활성화 (상)
    st=GOOD
    nfs=`lssrc -g nfs 2>/dev/null | awk '/nfsd|biod|rpc.mountd/ && /active/'`
    detail "NFS 데몬 상태:"; lssrc -g nfs 2>/dev/null | tee -a "$OUT"
    [ -n "$nfs" ] && { st=MANUAL; detail "NFS 구동 중 -> 필요성 확인 (불필요 시 취약)"; }
    result U-39 상 "불필요한 NFS 서비스 비활성화" $st
}

u40() { # NFS 접근 통제 (상)
    st=GOOD
    if [ -f /etc/exports ]; then
        detail "/etc/exports:"; cat /etc/exports | tee -a "$OUT"
        grep -Ev '^#' /etc/exports | grep -Eq '\-.*ro|\-.*access|\-.*root' || { st=MANUAL; detail "everyone(전체) export 가능성 -> 확인"; }
        grep -Eq '^/.*[[:space:]]*$|\*' /etc/exports && { st=VULN; detail "접근제어 없는 export 존재 -> 취약"; }
    else detail "/etc/exports 미존재(양호)"; fi
    result U-40 상 "NFS 접근 통제" $st
}

u41() { # 불필요한 automountd 제거 (상)
    st=GOOD
    am=`ps -ef | grep -i automount | grep -v grep`
    detail "automountd 프로세스: ${am:-(없음)}"
    [ -n "$am" ] && { st=MANUAL; detail "automountd 구동 중 -> 필요성 확인"; }
    result U-41 상 "불필요한 automountd 제거" $st
}

u42() { # 불필요한 RPC 서비스 비활성화 (상)
    st=GOOD
    rpcs="rstatd rusersd rwalld sprayd pcnfsd rquotad ttdbserver cmsd"
    found=""
    for s in $rpcs; do
        [ "`inetd_active $s`" = ACTIVE ] && found="$found $s"
    done
    detail "활성 RPC 서비스:${found:- (없음)}"
    [ -n "$found" ] && st=VULN
    result U-42 상 "불필요한 RPC 서비스 비활성화" $st
}

u43() { # NIS, NIS+ 점검 (상)
    st=GOOD
    nis=`ps -ef | grep -iE 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep`
    detail "NIS 프로세스: ${nis:-(없음)}"
    [ -n "$nis" ] && { st=MANUAL; detail "NIS 구동 중 -> 필요 시 NIS+ 사용 권고"; }
    result U-43 상 "NIS, NIS+ 점검" $st
}

u44() { chk_inetd U-44 상 "tftp, talk 서비스 비활성화" tftp talk ntalk; }

u45() { # 메일 서비스 버전 점검 (상)
    st=MANUAL
    sm=`ps -ef | grep -i sendmail | grep -v grep`
    detail "sendmail 프로세스: ${sm:-(없음)}"
    if [ -n "$sm" ]; then
        v=`echo '$Z' | /usr/sbin/sendmail -bt -d0 2>/dev/null | grep -i version`
        detail "sendmail 버전: $v -> 최신 패치 여부 확인"
    fi
    result U-45 상 "메일 서비스 버전 점검" $st
}

u46() { # 일반 사용자의 메일 서비스 실행 방지 (상)
    st=MANUAL
    detail "sendmail.cf의 PrivacyOptions에 restrictqrun 포함 여부 확인"
    grep -i 'PrivacyOptions' /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null | tee -a "$OUT"
    result U-46 상 "일반 사용자의 메일 서비스 실행 방지" $st
}

u47() { # 스팸 메일 릴레이 제한 (상)
    st=MANUAL
    detail "sendmail relay 제한(R\$* 규칙/access DB) 확인"
    grep -i 'relay' /etc/mail/sendmail.cf 2>/dev/null | head | tee -a "$OUT"
    sm=`ps -ef | grep -i sendmail | grep -v grep`
    [ -z "$sm" ] && { detail "메일서비스 미사용"; st=GOOD; }
    result U-47 상 "스팸 메일 릴레이 제한" $st
}

u48() { # expn, vrfy 명령어 제한 (중)
    st=GOOD
    opt=`grep -i 'PrivacyOptions' /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null`
    detail "PrivacyOptions: ${opt:-(확인불가)}"
    sm=`ps -ef | grep -i sendmail | grep -v grep`
    if [ -n "$sm" ]; then
        echo "$opt" | grep -iq 'noexpn' && echo "$opt" | grep -iq 'novrfy' || st=VULN
    else detail "메일서비스 미사용(양호)"; fi
    result U-48 중 "expn, vrfy 명령어 제한" $st
}

u49() { # DNS 보안 버전 패치 (상)
    st=MANUAL
    nd=`ps -ef | grep -i named | grep -v grep`
    detail "named(BIND) 프로세스: ${nd:-(없음)}"
    [ -n "$nd" ] && { v=`named -v 2>/dev/null`; detail "BIND 버전: $v -> 최신 패치 확인"; }
    [ -z "$nd" ] && st=GOOD
    result U-49 상 "DNS 보안 버전 패치" $st
}

u50() { # DNS Zone Transfer 설정 (상)
    st=GOOD
    if [ -f /etc/named.conf ]; then
        detail "named.conf allow-transfer 설정:"
        grep -i 'allow-transfer' /etc/named.conf | tee -a "$OUT"
        grep -i 'allow-transfer' /etc/named.conf >/dev/null || { st=VULN; detail "allow-transfer 미제한 -> 취약"; }
    else detail "/etc/named.conf 미존재 (DNS 미사용 양호)"; fi
    result U-50 상 "DNS Zone Transfer 설정" $st
}

u51() { # DNS 취약한 동적 업데이트 (중)
    st=GOOD
    if [ -f /etc/named.conf ]; then
        grep -i 'allow-update' /etc/named.conf | tee -a "$OUT"
        grep -i 'allow-update.*any' /etc/named.conf >/dev/null && { st=VULN; detail "allow-update {any} -> 취약"; }
    else detail "DNS 미사용(양호)"; fi
    result U-51 중 "DNS 서비스의 취약한 동적 업데이트 설정 금지" $st
}

u52() { chk_inetd U-52 중 "Telnet 서비스 비활성화" telnet; }

u53() { # FTP 서비스 정보 노출 제한 (하)
    st=MANUAL
    detail "FTP 배너 정보 노출 확인 (/etc/ftpd 배너 등)"
    [ "`inetd_active ftp`" = ACTIVE ] && detail "ftp inetd 활성" || detail "ftp inetd 비활성"
    result U-53 하 "FTP 서비스 정보 노출 제한" $st
}

u54() { # 암호화되지 않는 FTP 서비스 비활성화 (중)
    st=GOOD
    [ "`inetd_active ftp`" = ACTIVE ] && { st=VULN; detail "평문 ftp 서비스 활성 -> 취약(SFTP/FTPS 권고)"; } || detail "평문 ftp 비활성(양호)"
    result U-54 중 "암호화되지 않는 FTP 서비스 비활성화" $st
}

u55() { # FTP 계정 Shell 제한 (중)
    st=MANUAL
    detail "ftp 계정 shell이 /bin/false 등으로 제한되었는지 확인"
    grep -i '^ftp:' /etc/passwd | tee -a "$OUT"
    result U-55 중 "FTP 계정 Shell 제한" $st
}

u56() { # FTP 서비스 접근 제어 설정 (하)
    st=MANUAL
    detail "ftpaccess/hosts.allow 등 FTP 접근제어 확인"
    ls -l /etc/ftpaccess 2>/dev/null | tee -a "$OUT"
    result U-56 하 "FTP 서비스 접근 제어 설정" $st
}

u57() { # Ftpusers 파일 설정 (중)
    st=GOOD
    if [ -f /etc/ftpusers ]; then
        detail "/etc/ftpusers 내용:"; cat /etc/ftpusers | tee -a "$OUT"
        grep -q '^root' /etc/ftpusers || { st=VULN; detail "root가 ftpusers에 없음 -> 취약"; }
    else
        [ "`inetd_active ftp`" = ACTIVE ] && { st=VULN; detail "ftp 활성인데 /etc/ftpusers 없음 -> 취약"; } || detail "ftp 미사용(양호)"
    fi
    result U-57 중 "Ftpusers 파일 설정" $st
}

u58() { # 불필요한 SNMP 서비스 구동 점검 (중)
    st=GOOD
    sn=`lssrc -s snmpd 2>/dev/null | grep active`
    detail "snmpd 상태: ${sn:-(비활성)}"
    [ -n "$sn" ] && { st=MANUAL; detail "SNMP 구동 중 -> 필요성 확인"; }
    result U-58 중 "불필요한 SNMP 서비스 구동 점검" $st
}

u59() { # 안전한 SNMP 버전 사용 (상)
    st=GOOD
    sn=`lssrc -s snmpd 2>/dev/null | grep active`
    if [ -n "$sn" ]; then
        cfg=/etc/snmpdv3.conf
        [ -f $cfg ] && detail "snmpdv3.conf 사용(v3 가능)" || { detail "v1/v2c 추정"; st=VULN; }
        detail "판단: SNMP v3 사용 시 양호, v1/v2c 사용 시 취약"
        st=MANUAL
    else detail "SNMP 미사용(양호)"; fi
    result U-59 상 "안전한 SNMP 버전 사용" $st
}

u60() { # SNMP Community String 복잡성 (중)
    st=GOOD
    if [ -f /etc/snmpd.conf ]; then
        com=`grep -i '^community' /etc/snmpd.conf | awk '{print $2}'`
        detail "community string: $com  (public/private 사용 시 취약)"
        echo "$com" | grep -Eqw 'public|private' && st=VULN
    elif [ -f /etc/snmpdv3.conf ]; then
        com=`grep -i 'COMMUNITY' /etc/snmpdv3.conf | awk '{print $2}'`
        detail "v3 community: $com"
        echo "$com" | grep -Eqw 'public|private' && st=VULN
    else detail "SNMP 설정파일 없음(미사용 양호)"; fi
    result U-60 중 "SNMP Community String 복잡성 설정" $st
}

u61() { # SNMP Access Control 설정 (상)
    st=MANUAL
    detail "SNMP 접근 허용 IP 제한 설정 확인"
    grep -i 'community\|VACM\|access' /etc/snmpd.conf /etc/snmpdv3.conf 2>/dev/null | head | tee -a "$OUT"
    sn=`lssrc -s snmpd 2>/dev/null | grep active`
    [ -z "$sn" ] && { detail "SNMP 미사용(양호)"; st=GOOD; }
    result U-61 상 "SNMP Access Control 설정" $st
}

u62() { # 로그인 시 경고 메시지 설정 (하)
    st=GOOD
    detail "경고메시지 파일 확인: /etc/motd, /etc/security/login.cfg(herald)"
    [ -s /etc/motd ] && detail "/etc/motd 설정됨" || { st=VULN; detail "/etc/motd 미설정"; }
    her=`lssec -f /etc/security/login.cfg -s default -a herald 2>/dev/null`
    detail "herald: ${her:-(미설정)}"
    result U-62 하 "로그인 시 경고 메시지 설정" $st
}

u63() { # sudo 명령어 접근 관리 (중)
    st=MANUAL
    if [ -f /etc/sudoers ]; then
        detail "/etc/sudoers ALL 권한 부여 확인:"
        grep -Ev '^#|^$' /etc/sudoers 2>/dev/null | grep -i 'ALL' | tee -a "$OUT"
    else detail "sudo 미설치/미사용"; st=GOOD; fi
    result U-63 중 "sudo 명령어 접근 관리" $st
}

#==============================================================================
# 4. 패치 관리 (U-64)
#==============================================================================
u64() { # 주기적 보안 패치 및 벤더 권고사항 적용 (상)
    st=MANUAL
    detail "OS Level: `oslevel -s 2>/dev/null`"
    detail "최근 설치 fileset(최근10):"; lslpp -h 2>/dev/null | head -10 | tee -a "$OUT"
    detail "판단: 최신 TL/SP 및 벤더(IBM) 보안권고 적용 여부를 운영자/벤더와 확인"
    result U-64 상 "주기적 보안 패치 및 벤더 권고사항 적용" $st
}

#==============================================================================
# 5. 로그 관리 (U-65 ~ U-67)
#==============================================================================
u65() { # NTP 및 시각 동기화 설정 (중)
    st=VULN
    nt=`lssrc -s xntpd 2>/dev/null | grep active`
    detail "xntpd 상태: ${nt:-(비활성)}"
    [ -n "$nt" ] && st=GOOD
    [ -f /etc/ntp.conf ] && { detail "/etc/ntp.conf server 설정:"; grep -i '^server' /etc/ntp.conf | tee -a "$OUT"; }
    [ "$st" = VULN ] && detail "NTP 미동작 -> 취약 (시각동기화 필요)"
    result U-65 중 "NTP 및 시각 동기화 설정" $st
}

u66() { # 정책에 따른 시스템 로깅 설정 (중)
    st=GOOD
    if [ -f /etc/syslog.conf ]; then
        detail "/etc/syslog.conf 활성 설정:"; grep -Ev '^#|^$' /etc/syslog.conf | tee -a "$OUT"
        grep -Ev '^#|^$' /etc/syslog.conf | grep -q . || { st=VULN; detail "로깅 설정 없음 -> 취약"; }
    else st=VULN; detail "/etc/syslog.conf 미존재 -> 취약"; fi
    result U-66 중 "정책에 따른 시스템 로깅 설정" $st
}

u67() { # 로그 디렉터리 소유자 및 권한 설정 (중)
    st=GOOD
    detail "로그 디렉토리 권한:"
    ls -ld /var/log /var/adm 2>/dev/null | tee -a "$OUT"
    bad=`find /var/adm /var/log -type d -perm -022 2>/dev/null`
    [ -n "$bad" ] && { st=VULN; detail "타사용자 쓰기가능 로그 디렉토리: $bad"; }
    result U-67 중 "로그 디렉터리 소유자 및 권한 설정" $st
}

#==============================================================================
# MAIN
#==============================================================================
> "$OUT"
header

log ""
log "===== 1. 계정 관리 ====="
u01; u02; u03; u04; u05; u06; u07; u08; u09; u10; u11; u12; u13

log ""
log "===== 2. 파일 및 디렉터리 관리 ====="
u14; u15; u16; u17; u18; u19; u20; u21; u22; u23; u24; u25; u26; u27; u28; u29; u30; u31; u32; u33

log ""
log "===== 3. 서비스 관리 ====="
u34; u35; u36; u37; u38; u39; u40; u41; u42; u43; u44; u45; u46; u47; u48; u49; u50; u51; u52; u53; u54; u55; u56; u57; u58; u59; u60; u61; u62; u63

log ""
log "===== 4. 패치 관리 ====="
u64

log ""
log "===== 5. 로그 관리 ====="
u65; u66; u67

log ""
log "########################################################################"
log "# 점검 요약"
log "#   [양호] GOOD   : $CNT_GOOD"
log "#   [취약] VULN   : $CNT_VULN"
log "#   [수동] MANUAL : $CNT_MANUAL  (근거자료 수집됨, 운영자 판단 필요)"
log "#   [N/A]         : $CNT_NA"
log "#   결과파일      : $OUT"
log "########################################################################"
