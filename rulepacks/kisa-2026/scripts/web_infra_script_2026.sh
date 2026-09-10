#!/bin/ksh
#==============================================================================
# 웹 서비스 주요정보통신기반시설 취약점 점검 (WEB-01 ~ WEB-26)
# 기준 : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드
# 대상 : Tomcat / WebTier(OHS, Apache 계열) / WebLogic
#
# !! 읽기 전용 : grep/ls/ps 만 수행, 설정 변경 없음 !!
#
# 사용법:
#   아래 [설정] 의 경로 변수를 환경에 맞게 채운 뒤 실행.
#   해당 제품 경로가 비어 있으면 그 제품 점검은 건너뜀(여러 개 동시 가능).
#   $ ./kisa_web_check.sh
#
# 판정 : WEB-XX(제품) | 양호|취약|수동|N/A | 근거
#   (제품: T=Tomcat, O=OHS/WebTier, W=WebLogic)
#   HTTP 응답 실제확인이 필요한 항목(WEB-16/20 등)은 설정파일 기준 1차판정 + 수동표기
#==============================================================================

LANG=C; export LANG

#============================= [설정] 경로 지정 ===============================
# Tomcat : CATALINA_BASE(또는 설치 디렉터리). conf/, logs/, webapps/ 의 상위
TOMCAT_HOME="${TOMCAT_HOME:-}"            # 예: /opt/tomcat  또는  배치서버 자체 Tomcat 경로

# WebTier(OHS) : httpd.conf 가 있는 디렉터리 (instance config)
#   12cR2 예: $DOMAIN_HOME/config/fmwconfig/components/OHS/<instance>
OHS_CONF_DIR="${OHS_CONF_DIR:-}"          # httpd.conf, ssl.conf, *.conf 위치
OHS_BIN="${OHS_BIN:-}"                    # (선택) httpd 실행파일 경로 - 버전확인용

# WebLogic : DOMAIN_HOME (config/config.xml 의 상위)
WL_DOMAIN_HOME="${WL_DOMAIN_HOME:-}"      # 예: /opt/oracle/user_projects/domains/base_domain
#=============================================================================

HOSTN=`hostname`
TODAY=`date +%Y%m%d_%H%M%S`
OUT="./kisa_web_result_${HOSTN}_${TODAY}.txt"

log() { echo "$*" | tee -a "$OUT"; }
emit() { log "$1 | $2 | $3"; }            # emit <CODE(제품)> <STATUS> <근거>
dt()  { log "    >> $*"; }

# 주석(<!-- -->, #) 제외하고 활성 라인에서 패턴 검색. echo: 매칭라인 또는 빈값
act_grep() { grep -i "$2" "$1" 2>/dev/null | grep -v '<!--' | grep -v '^[[:space:]]*#'; }

# 파일이 other(타 사용자) 접근권한 있는지: echo "BAD"/"OK"/"NF"
other_access() {
    [ -f "$1" ] || { echo NF; return; }
    p=`ls -l "$1" 2>/dev/null | awk '{print $1}'`
    o=`echo "$p" | cut -c8-10`
    case "$o" in ---) echo OK;; *) echo BAD;; esac
}

> "$OUT"
log "########################################################################"
log "# 웹 서비스 취약점 점검 결과 (KISA WEB-01~WEB-26)"
log "# HOST : $HOSTN    DATE: `date`"
log "# Tomcat   : ${TOMCAT_HOME:-(미지정)}"
log "# OHS conf : ${OHS_CONF_DIR:-(미지정)}"
log "# WebLogic : ${WL_DOMAIN_HOME:-(미지정)}"
log "# (Read-Only 점검 / 설정 변경 없음)"
log "########################################################################"

#==============================================================================
# Tomcat 모듈
#==============================================================================
check_tomcat() {
    T="$TOMCAT_HOME"
    SX="$T/conf/server.xml"; WX="$T/conf/web.xml"; TU="$T/conf/tomcat-users.xml"; CX="$T/conf/context.xml"
    log ""
    log "===================================================================="
    log "== [Tomcat]  $T"
    log "===================================================================="

    # WEB-01 기본 관리자 계정/관리자 페이지
    if [ -f "$TU" ]; then
        du=`act_grep "$TU" 'username=' | grep -iE 'username="(admin|tomcat|manager)"'`
        mg=`act_grep "$TU" 'manager-gui'`
        dt "tomcat-users: `act_grep "$TU" 'username=' | tr '\n' ' '`"
        if [ -n "$du" ] || [ -n "$mg" ]; then emit "WEB-01(T)" 취약 "기본계정명(admin/tomcat/manager) 또는 manager-gui 활성"
        else emit "WEB-01(T)" 양호 "기본 관리자 계정/페이지 미사용"; fi
    else emit "WEB-01(T)" 양호 "tomcat-users.xml 없음(관리자 페이지 미사용 추정)"; fi

    # WEB-02 취약한 비밀번호 (평문여부만 자동, 복잡도는 수동)
    if [ -f "$TU" ] && act_grep "$TU" 'password=' | grep -qiv 'password=""'; then
        emit "WEB-02(T)" 수동 "tomcat-users.xml 평문 password 존재 - 복잡도 수동확인"
    else emit "WEB-02(T)" 양호 "설정된 평문 비밀번호 없음/계정 미사용"; fi

    # WEB-03 비밀번호 파일 권한 (tomcat-users.xml <= 600)
    case `other_access "$TU"` in
        OK) emit "WEB-03(T)" 양호 "tomcat-users.xml 타사용자 접근권한 없음" ;;
        BAD) dt "`ls -l "$TU"`"; emit "WEB-03(T)" 취약 "tomcat-users.xml 타사용자 접근권한 존재(600 이하 권고)" ;;
        NF) emit "WEB-03(T)" 양호 "tomcat-users.xml 없음" ;;
    esac

    # WEB-04 디렉터리 리스팅 (web.xml listings=false)
    if [ -f "$WX" ]; then
        lst=`grep -izoP 'listings</param-name>\s*<param-value>\s*true' "$WX" 2>/dev/null`
        lst2=`act_grep "$WX" 'listings' | grep -i 'true'`
        if [ -n "$lst" ] || [ -n "$lst2" ]; then emit "WEB-04(T)" 취약 "web.xml listings=true(디렉터리 리스팅 허용)"
        else emit "WEB-04(T)" 양호 "디렉터리 리스팅 비활성(listings=false/미설정)"; fi
    else emit "WEB-04(T)" 수동 "web.xml 미확인"; fi

    # WEB-05 CGI 매핑
    if [ -f "$WX" ] && act_grep "$WX" 'cgi' | grep -qi 'servlet'; then
        emit "WEB-05(T)" 취약 "web.xml CGI servlet 매핑 활성(경로제한 수동확인)"
    else emit "WEB-05(T)" 양호 "CGI 매핑 비활성"; fi

    # WEB-06 상위 디렉터리 접근 (allowLinking=true)
    al=`act_grep "$SX" 'allowLinking="true"'; act_grep "$CX" 'allowLinking="true"'`
    if [ -n "$al" ]; then emit "WEB-06(T)" 취약 "allowLinking=true(상위/심볼릭 접근 허용)"
    else emit "WEB-06(T)" 양호 "allowLinking 미사용"; fi

    # WEB-07 불필요 기본 파일/디렉터리
    extra=""
    for d in docs examples host-manager manager ROOT/RELEASE-NOTES.txt; do
        [ -e "$T/webapps/$d" ] && extra="$extra $d"
    done
    if [ -n "$extra" ]; then dt "존재:$extra"; emit "WEB-07(T)" 취약 "기본 샘플/매뉴얼 존재:$extra (제거 권고)"
    else emit "WEB-07(T)" 양호 "기본 샘플/매뉴얼 디렉터리 없음"; fi

    # WEB-08 업로드/다운로드 용량 제한
    if [ -f "$SX" ] && act_grep "$SX" 'maxPostSize' >/dev/null; then
        emit "WEB-08(T)" 양호 "maxPostSize 설정됨: `act_grep "$SX" 'maxPostSize' | tr '\n' ' '`"
    elif [ -f "$WX" ] && act_grep "$WX" 'max-file-size' >/dev/null; then
        emit "WEB-08(T)" 양호 "multipart max-file-size 설정됨"
    else emit "WEB-08(T)" 취약 "업로드/다운로드 용량제한 미설정(maxPostSize/max-file-size)"; fi

    # WEB-09 프로세스 권한 (root 구동 금지)
    powner=`ps -ef | grep -i 'catalina\|tomcat' | grep -v grep | awk '{print $1}' | head -1`
    if [ -z "$powner" ]; then emit "WEB-09(T)" 수동 "Tomcat 프로세스 미탐지 - 구동/계정 수동확인"
    elif [ "$powner" = "root" ]; then emit "WEB-09(T)" 취약 "root 권한 구동"
    else emit "WEB-09(T)" 양호 "비-root 구동(owner=$powner)"; fi

    # WEB-13 설정 파일(DB연결정보) 노출 - server.xml 권한 600
    if [ -f "$SX" ] && act_grep "$SX" 'password=' | grep -qi 'Resource'; then
        case `other_access "$SX"` in
          OK) emit "WEB-13(T)" 양호 "DB Resource 존재하나 server.xml 접근권한 제한됨" ;;
          *)  emit "WEB-13(T)" 취약 "server.xml에 DB연결 정보 존재 + 권한 미흡(600 권고)" ;;
        esac
    else emit "WEB-13(T)" 양호 "server.xml 내 노출 DB연결정보 없음"; fi

    # WEB-14 설정파일 접근통제 (conf/*)
    bad14=`find "$T/conf" -type f -perm -004 2>/dev/null | head`
    if [ -n "$bad14" ]; then dt "타사용자 읽기가능 conf 파일 존재"; emit "WEB-14(T)" 취약 "conf 디렉터리 파일에 타사용자 접근권한 존재"
    else emit "WEB-14(T)" 양호 "conf 파일 타사용자 접근권한 없음"; fi

    # WEB-15 불필요 스크립트 매핑 - 수동
    emit "WEB-15(T)" 수동 "web.xml servlet-mapping 중 불필요 매핑 존재여부 수동확인"

    # WEB-17 가상 디렉터리 (Context path)
    if [ -f "$SX" ] && act_grep "$SX" 'Context' | grep -qi 'path='; then
        emit "WEB-17(T)" 수동 "server.xml Context path= 존재 - 불필요 가상디렉터리 수동확인"
    else emit "WEB-17(T)" 양호 "불필요 Context(가상디렉터리) 없음"; fi

    # WEB-16 헤더 정보 노출 (Connector server= / showServerInfo=false)
    si=`act_grep "$SX" 'showServerInfo="false"'`
    sv=`act_grep "$SX" 'server="' | grep -vi 'server="Apache' | grep -i 'server='`
    if [ -n "$si" ] || [ -n "$sv" ]; then emit "WEB-16(T)" 수동 "server명 변경/showServerInfo=false 설정됨(실제응답 헤더 curl 확인 권고)"
    else emit "WEB-16(T)" 취약 "Connector server= 미변경 및 showServerInfo 미설정(버전 노출 가능)"; fi

    # WEB-19 SSI 사용 제한
    if [ -f "$WX" ] && act_grep "$WX" 'ssi' | grep -qiE 'servlet|filter'; then
        emit "WEB-19(T)" 취약 "web.xml SSIServlet/SSIFilter 활성"
    else emit "WEB-19(T)" 양호 "SSI 비활성"; fi

    # WEB-22 에러 페이지 관리
    if [ -f "$WX" ] && act_grep "$WX" 'error-page' >/dev/null; then
        emit "WEB-22(T)" 양호 "web.xml error-page 지정됨"
    else emit "WEB-22(T)" 취약 "일원화된 error-page 미지정(기본 에러페이지 노출)"; fi

    # WEB-23 LDAP digest 알고리즘
    dg=`act_grep "$SX" 'digest='`
    if [ -z "$dg" ]; then emit "WEB-23(T)" 양호 "LDAP digest 미사용(해당없음)"
    elif echo "$dg" | grep -qiE 'SHA-256|SHA-512|SHA256|SHA512'; then emit "WEB-23(T)" 양호 "안전한 digest 사용: `echo $dg`"
    else emit "WEB-23(T)" 취약 "취약 digest(SSHA/SHA-1 등): `echo $dg`"; fi

    # WEB-24 별도 업로드 경로 - 수동
    emit "WEB-24(T)" 수동 "업로드 경로 분리/권한 운영정책 수동확인"

    # WEB-25 패치/버전 - 수동
    ver="(수동확인)"
    [ -f "$T/lib/catalina.jar" ] && ver="catalina.jar 존재(버전: java -cp catalina.jar org.apache.catalina.util.ServerInfo)"
    emit "WEB-25(T)" 수동 "Tomcat 버전/최신패치 수동확인 - $ver"

    # WEB-26 로그 디렉터리/파일 권한
    badlog=`find "$T/logs" -type f -perm -004 2>/dev/null | head`
    if [ -d "$T/logs" ]; then
        if [ -n "$badlog" ]; then emit "WEB-26(T)" 취약 "logs 파일에 타사용자 읽기권한 존재(o-rwx 권고)"
        else emit "WEB-26(T)" 양호 "로그 파일 타사용자 접근권한 없음"; fi
    else emit "WEB-26(T)" 수동 "logs 디렉터리 미확인($T/logs)"; fi

    # Tomcat 미해당
    emit "WEB-20(T)" N/A "SSL/TLS - Tomcat은 가이드 대상 아님(앞단 OHS/LB에서 처리)"
    for c in WEB-10 WEB-11 WEB-12 WEB-18 WEB-21; do
        emit "$c(T)" N/A "Apache/Nginx/IIS 계열 항목 - Tomcat 미해당"
    done
}

#==============================================================================
# WebTier (OHS / Apache 계열) 모듈
#==============================================================================
check_ohs() {
    D="$OHS_CONF_DIR"
    # httpd.conf 및 포함된 *.conf 전체를 한 번에 검색 대상으로
    CONFS=`ls "$D"/httpd.conf "$D"/ssl.conf "$D"/*.conf "$D"/moduleconf/*.conf 2>/dev/null | sort -u`
    [ -z "$CONFS" ] && CONFS="$D/httpd.conf"
    log ""
    log "===================================================================="
    log "== [WebTier/OHS]  $D"
    log "===================================================================="
    dt "검색 대상 conf: `echo $CONFS | tr '\n' ' '`"

    ag() { grep -ih "$1" $CONFS 2>/dev/null | grep -v '^[[:space:]]*#'; }

    # WEB-04 디렉터리 리스팅 (Options Indexes)
    if ag 'Options' | grep -iwq 'Indexes' && ! ag 'Options' | grep -iq '\-Indexes'; then
        emit "WEB-04(O)" 취약 "Options에 Indexes 활성(디렉터리 리스팅)"
    else emit "WEB-04(O)" 양호 "디렉터리 리스팅 비활성(-Indexes/미설정)"; fi

    # WEB-05 CGI 실행 제한
    if ag 'LoadModule' | grep -iq 'cgi_module\|cgid_module' || ag 'Options' | grep -iwq 'ExecCGI'; then
        emit "WEB-05(O)" 수동 "CGI 모듈/ExecCGI 활성 - 실행 디렉터리 제한 수동확인"
    else emit "WEB-05(O)" 양호 "CGI 모듈/ExecCGI 비활성"; fi

    # WEB-09 프로세스 권한 (User 지시자 / 실제 프로세스)
    udir=`ag '^User' | awk '{print $2}' | head -1`
    powner=`ps -ef | grep -i 'httpd\|ohs' | grep -v grep | grep -v '^root .*-k start' | awk '{print $1}' | sort -u | grep -v '^root$' | head -1`
    if echo "$udir" | grep -qi 'root'; then emit "WEB-09(O)" 취약 "User 지시자=root"
    elif [ -n "$udir" ]; then emit "WEB-09(O)" 양호 "User 지시자=$udir (비-root)"
    else emit "WEB-09(O)" 수동 "User 지시자 미확인 - 구동계정 수동확인"; fi

    # WEB-10 불필요 프록시 설정
    if ag 'LoadModule' | grep -iq 'proxy_module'; then emit "WEB-10(O)" 수동 "mod_proxy 로드됨 - 필요성 수동확인"
    else emit "WEB-10(O)" 양호 "프록시 모듈 미사용"; fi

    # WEB-11 웹 서비스 경로 설정 (DocumentRoot) - 수동
    emit "WEB-11(O)" 수동 "DocumentRoot 경로 적정성 수동확인: `ag 'DocumentRoot' | tr '\n' ' '`"

    # WEB-12 링크(심볼릭) 사용 금지 (FollowSymLinks)
    if ag 'Options' | grep -iwq 'FollowSymLinks' && ! ag 'Options' | grep -iq '\-FollowSymLinks'; then
        emit "WEB-12(O)" 취약 "Options FollowSymLinks 활성(심볼릭 링크 허용)"
    else emit "WEB-12(O)" 양호 "FollowSymLinks 비활성"; fi

    # WEB-14 설정파일/디렉터리 접근통제 (conf 내 타사용자 읽기권한)
    bad14=`find "$D" -maxdepth 1 -type f -name '*.conf' -perm -004 2>/dev/null | head`
    if [ -n "$bad14" ]; then emit "WEB-14(O)" 취약 "conf 파일에 타사용자 접근권한 존재"
    else emit "WEB-14(O)" 양호 "conf 파일 타사용자 접근권한 없음"; fi

    # WEB-16 헤더 정보 노출 (ServerTokens Prod / ServerSignature Off)
    st=`ag 'ServerTokens' | awk '{print $2}' | head -1`
    ss=`ag 'ServerSignature' | awk '{print $2}' | head -1`
    if echo "$st" | grep -qi 'Prod' && echo "$ss" | grep -qi 'Off'; then
        emit "WEB-16(O)" 양호 "ServerTokens=$st, ServerSignature=$ss"
    else emit "WEB-16(O)" 취약 "ServerTokens=${st:-미설정}, ServerSignature=${ss:-미설정} (Prod/Off 권고)"; fi

    # WEB-17 가상 디렉터리 (Alias) - 수동
    al=`ag 'Alias'`
    if [ -n "$al" ]; then emit "WEB-17(O)" 수동 "Alias 존재 - 불필요 가상디렉터리 수동확인"
    else emit "WEB-17(O)" 양호 "불필요 Alias 없음"; fi

    # WEB-18 WebDAV 비활성화 (Dav On)
    if ag 'Dav' | grep -iwq 'On'; then emit "WEB-18(O)" 취약 "WebDAV(Dav On) 활성"
    else emit "WEB-18(O)" 양호 "WebDAV 비활성"; fi

    # WEB-19 SSI (Options Includes)
    if ag 'Options' | grep -iwq 'Includes' && ! ag 'Options' | grep -iq '\-Includes'; then
        emit "WEB-19(O)" 취약 "Options Includes 활성(SSI 허용)"
    else emit "WEB-19(O)" 양호 "SSI 비활성"; fi

    # WEB-20 SSL/TLS 활성화
    if ag 'SSLEngine' | grep -iwq 'on' || ag 'LoadModule' | grep -iq 'ssl_module'; then
        emit "WEB-20(O)" 양호 "SSL/TLS 활성(SSLEngine on/mod_ssl)"
    else emit "WEB-20(O)" 취약 "SSL/TLS 미활성"; fi

    # WEB-21 HTTP->HTTPS 리디렉션
    if ag 'Redirect' | grep -qi 'https' || ag 'RewriteRule' | grep -qi 'https'; then
        emit "WEB-21(O)" 양호 "HTTPS 리디렉션 설정됨"
    else emit "WEB-21(O)" 취약 "HTTP->HTTPS 리디렉션 미설정"; fi

    # WEB-22 에러 페이지 (ErrorDocument)
    if ag 'ErrorDocument' >/dev/null 2>&1 && [ -n "`ag 'ErrorDocument'`" ]; then
        emit "WEB-22(O)" 양호 "ErrorDocument 지정됨"
    else emit "WEB-22(O)" 취약 "ErrorDocument 미지정(기본 에러페이지 노출)"; fi

    # WEB-24 업로드 경로 - 수동
    emit "WEB-24(O)" 수동 "업로드 경로 분리/권한 운영정책 수동확인"

    # WEB-25 패치/버전 - 수동
    v="(수동확인: httpd -v)"; [ -n "$OHS_BIN" ] && [ -x "$OHS_BIN" ] && v=`"$OHS_BIN" -v 2>/dev/null | head -1`
    emit "WEB-25(O)" 수동 "OHS/Apache 버전·최신패치 수동확인 - $v"

    # WEB-26 로그 권한
    LOGD=`ag 'CustomLog' | awk '{print $2}' | head -1`
    if [ -n "$LOGD" ] && [ -e "$LOGD" ]; then
        if [ "`other_access "$LOGD"`" = OK ]; then emit "WEB-26(O)" 양호 "로그파일 타사용자 접근권한 없음"
        else dt "`ls -l "$LOGD" 2>/dev/null`"; emit "WEB-26(O)" 취약 "로그파일 타사용자 접근권한 존재(o-rwx 권고)"; fi
    else emit "WEB-26(O)" 수동 "로그 경로 자동확인 불가 - 수동확인"; fi

    # OHS 미해당 (Tomcat/IIS/JEUS 전용)
    for c in WEB-01 WEB-02 WEB-03 WEB-13 WEB-15 WEB-23; do
        emit "$c(O)" N/A "Tomcat/IIS/JEUS 전용 항목 - OHS 미해당"
    done
    emit "WEB-06(O)" 수동 "AllowOverride/상위경로 접근제한 수동확인: `ag 'AllowOverride' | tr '\n' ' '`"
    emit "WEB-07(O)" 수동 "기본 manual/sample 파일 제거여부 수동확인(htdocs/manual 등)"
    emit "WEB-08(O)" 수동 "LimitRequestBody(업로드 용량제한) 수동확인: `ag 'LimitRequestBody' | tr '\n' ' '`"
}

#==============================================================================
# WebLogic 모듈 (가이드 명시 대상 아님: 적용 가능한 항목만 + 나머지 WAS-N/A)
#==============================================================================
check_weblogic() {
    H="$WL_DOMAIN_HOME"; CFG="$H/config/config.xml"
    BP=`ls "$H"/servers/*/security/boot.properties 2>/dev/null | head -1`
    log ""
    log "===================================================================="
    log "== [WebLogic]  $H   (※가이드 명시 대상 아님 - WAS 관점 적용)"
    log "===================================================================="

    # WEB-01 기본 관리자 계정(weblogic) - boot.properties 기반 수동
    if [ -n "$BP" ]; then
        u=`grep -i '^username=' "$BP" 2>/dev/null | cut -d= -f2`
        dt "boot.properties username(암호화여부 확인): ${u:-(암호화/미확인)}"
        if echo "$u" | grep -qiw 'weblogic'; then emit "WEB-01(W)" 취약 "기본 관리자 계정명 weblogic 사용(변경 권고)"
        else emit "WEB-01(W)" 수동 "관리자 계정명 수동확인(boot.properties)"; fi
    else emit "WEB-01(W)" 수동 "boot.properties 미발견 - 관리자 계정 수동확인"; fi

    # WEB-03/14 주요 설정/자격 파일 권한 (config.xml, boot.properties, SerializedSystemIni.dat)
    bad=0
    for f in "$CFG" "$BP" `ls "$H"/security/SerializedSystemIni.dat 2>/dev/null`; do
        [ -f "$f" ] || continue
        a=`other_access "$f"`
        dt "`ls -l "$f" 2>/dev/null`"
        [ "$a" = BAD ] && bad=1
    done
    if [ "$bad" = 1 ]; then emit "WEB-14(W)" 취약 "config.xml/boot.properties 등 자격파일에 타사용자 접근권한 존재"
    else emit "WEB-14(W)" 양호 "주요 설정/자격 파일 타사용자 접근권한 없음"; fi

    # WEB-09 프로세스 권한 (weblogic.Server / java not root)
    powner=`ps -ef | grep -i 'weblogic.Server\|weblogic.Name' | grep -v grep | awk '{print $1}' | head -1`
    if [ -z "$powner" ]; then emit "WEB-09(W)" 수동 "WebLogic 프로세스 미탐지 - 구동/계정 수동확인"
    elif [ "$powner" = "root" ]; then emit "WEB-09(W)" 취약 "root 권한 구동"
    else emit "WEB-09(W)" 양호 "비-root 구동(owner=$powner)"; fi

    # WEB-22 에러 페이지 (config.xml / 도메인 정책) - 수동
    emit "WEB-22(W)" 수동 "에러페이지(error-page) 일원화 설정 수동확인"

    # WEB-25 패치/버전 - 수동
    emit "WEB-25(W)" 수동 "WebLogic 버전/PSU 수동확인 (java weblogic.version 또는 OPatch lsinventory)"

    # WEB-26 로그 권한 (도메인 servers/*/logs)
    badlog=`find "$H"/servers 2>/dev/null -path '*/logs/*' -type f -perm -004 2>/dev/null | head`
    if [ -d "$H/servers" ]; then
        if [ -n "$badlog" ]; then emit "WEB-26(W)" 취약 "도메인 logs 파일에 타사용자 읽기권한 존재"
        else emit "WEB-26(W)" 양호 "도메인 로그 파일 타사용자 접근권한 없음"; fi
    else emit "WEB-26(W)" 수동 "servers/*/logs 미확인"; fi

    # 그 외 항목 - WebLogic은 가이드 대상 아님
    for c in WEB-02 WEB-03 WEB-04 WEB-05 WEB-06 WEB-07 WEB-08 WEB-10 WEB-11 WEB-12 \
             WEB-13 WEB-15 WEB-16 WEB-17 WEB-18 WEB-19 WEB-20 WEB-21 WEB-23 WEB-24; do
        emit "$c(W)" N/A "가이드 명시 대상 아님(WebLogic은 WAS) - 미해당"
    done
}

#==============================================================================
# MAIN
#==============================================================================
[ -n "$TOMCAT_HOME" ]    && check_tomcat    || log "\n[skip] TOMCAT_HOME 미지정 - Tomcat 점검 생략"
[ -n "$OHS_CONF_DIR" ]   && check_ohs       || log "\n[skip] OHS_CONF_DIR 미지정 - WebTier/OHS 점검 생략"
[ -n "$WL_DOMAIN_HOME" ] && check_weblogic  || log "\n[skip] WL_DOMAIN_HOME 미지정 - WebLogic 점검 생략"

G=`grep -E '^WEB-[0-9]+\([TOW]\) \| 양호 ' "$OUT" | wc -l | tr -d ' '`
V=`grep -E '^WEB-[0-9]+\([TOW]\) \| 취약 ' "$OUT" | wc -l | tr -d ' '`
M=`grep -E '^WEB-[0-9]+\([TOW]\) \| 수동 ' "$OUT" | wc -l | tr -d ' '`
N=`grep -E '^WEB-[0-9]+\([TOW]\) \| N/A '  "$OUT" | wc -l | tr -d ' '`
T=`expr $G + $V + $M + $N`

log ""
log "########################################################################"
log "# 점검 요약 (WEB-01~WEB-26, 제품별)"
log "#   [양호] : $G"
log "#   [취약] : $V"
log "#   [수동] : $M   (근거 수집됨, 운영자 판단 필요)"
log "#   [N/A]  : $N"
log "#   합계   : $T"
log "#   결과파일: $OUT"
log "########################################################################"
log ""
log "[취약 항목 목록]"
grep -E '^WEB-[0-9]+\([TOW]\) \| 취약 ' "$OUT"
