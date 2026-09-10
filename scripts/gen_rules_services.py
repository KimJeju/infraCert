"""KISA 2026 서비스·로그 묶음(U-34~U-63, U-65~U-67) 선언형 YAML 생성기.

YAML 을 셸 heredoc 으로 쓰면 이스케이프가 증발하므로 dict → yaml.safe_dump 로 만든다.
룰 자체는 rulepacks/kisa-2026/rules/*.yaml 이 정본이고 이 파일은 재생성 도구다.
실행: python scripts/gen_rules_services.py  (그 뒤 scripts/regen_manifest.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
D = ROOT / "rulepacks" / "kisa-2026" / "rules"
ALL = ["linux", "aix", "solaris", "hpux"]


def svc_cmd(inetd: list[str], procs: list[str]) -> str:
    """활성 서비스 근거를 줄 단위로 출력. inetd.conf / xinetd / systemd / 프로세스."""
    parts = []
    for s in inetd:
        parts.append(f"grep -E '^[[:space:]]*{s}[[:space:]]' /etc/inetd.conf 2>/dev/null | sed 's/^/inetd: /'")
        parts.append(f"[ -f /etc/xinetd.d/{s} ] && grep -iqE 'disable[[:space:]]*=[[:space:]]*no' "
                     f"/etc/xinetd.d/{s} && echo 'xinetd: {s} enabled'")
        parts.append(f"systemctl is-active {s} {s}.socket 2>/dev/null | grep -x active | sed 's/^/systemd: {s} /'")
    if procs:
        alt = "|".join(procs)
        parts.append(f"ps -e -o comm= 2>/dev/null | grep -xE '({alt})' | sort -u | sed 's/^/proc: /'")
    return "; ".join(parts)


def lines_rule(rid, name, sev, cmd, timeout=60, nonzero="VULN", note="", platforms=ALL,
               cat="서비스관리", extra_collect=None, evidence=None):
    collect = [dict(key="found", cmd=cmd, timeout=timeout)] + (extra_collect or [])
    return dict(id=rid, name=name, severity=sev, category=cat, platforms=platforms,
                collect=collect, extract=[{"from": "found", "lines": "n"}],
                verdict=[{"when": {"found_ok": {"eq": "False"}, "n": {"eq": 0}}, "then": "MANUAL"},
                         {"when": {"n": {"eq": 0}}, "then": "GOOD"}, {"else": nonzero}],
                evidence=evidence or ["found"], note=note)


def rule(rid, name, sev, collect, verdict, evidence, note="", manual=False, platforms=ALL,
         extract=None, cat="서비스관리"):
    d = dict(id=rid, name=name, severity=sev, category=cat, platforms=platforms, collect=collect)
    if extract:
        d["extract"] = extract
    d.update(verdict=verdict, evidence=evidence, note=note)
    if manual:
        d["manual"] = True
    return d


R: dict[str, dict] = {}
R["U-34"] = lines_rule("U-34", "Finger 서비스 비활성화", "상",
                       svc_cmd(["finger"], ["fingerd", "in.fingerd"]),
                       note="finger 서비스가 inetd/xinetd/프로세스 어디서든 활성이면 취약")
R["U-35"] = rule(
    "U-35", "공유 서비스에 대한 익명 접근 제한 설정", "상",
    [dict(key="shares", cmd="grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports 2>/dev/null | sed 's/^/nfs: /'; "
                            "grep -iE '^[[:space:]]*(guest ok|map to guest|public)' /etc/samba/smb.conf 2>/dev/null | sed 's/^/smb: /'"),
     dict(key="anon", cmd="grep -vE '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -E '\\*|no_root_squash|insecure|anonuid'; "
                          "grep -iE '^[[:space:]]*(guest ok|map to guest)[[:space:]]*=[[:space:]]*(yes|bad user)' /etc/samba/smb.conf 2>/dev/null")],
    [{"when": {"shares": {"absent": True}}, "then": "GOOD"},
     {"when": {"anon": {"exists": True}}, "then": "VULN"},
     {"else": "MANUAL"}],
    ["shares"], note="공유 없음 양호. exports '*'/no_root_squash/insecure, smb guest ok 는 취약. 그 외 공유는 접근제어 확인")
R["U-36"] = lines_rule("U-36", "r 계열 서비스 비활성화(rlogin/rsh/rexec)", "상",
                       svc_cmd(["shell", "login", "exec", "rsh", "rlogin", "rexec"],
                               ["rshd", "rlogind", "rexecd", "in.rshd", "in.rlogind", "in.rexecd"]),
                       note="rsh/rlogin/rexec 활성이면 취약")
R["U-37"] = rule(
    "U-37", "crontab 설정파일 권한 설정", "상",
    [dict(key="ls", cmd="ls -ld /etc/crontab /etc/cron.d /var/spool/cron /var/spool/cron/crontabs /var/adm/cron 2>/dev/null"),
     dict(key="unreadable", cmd="for p in /etc/crontab /etc/cron.d /var/spool/cron /var/spool/cron/crontabs /var/adm/cron; do [ -e \"$p\" ] && [ ! -r \"$p\" ] && echo \"$p\"; done; true"),
     dict(key="found", cmd="find /etc/crontab /etc/cron.d /etc/cron.allow /etc/cron.deny /var/spool/cron /var/spool/cron/crontabs "
                           "/var/spool/cron/tabs /var/adm/cron -maxdepth 1 \\( -perm -o+w -o ! -user root -o \\( -type f -perm -g+w \\) \\) 2>/dev/null; true")],
    [{"when": {"found": {"exists": True}}, "then": "VULN"},
     {"when": {"unreadable": {"exists": True}}, "then": "MANUAL"},
     {"else": "GOOD"}],
    ["ls", "found", "unreadable"], note="cron 설정/스풀이 root 소유·other 쓰기 없음·파일 그룹쓰기 없음이어야 양호. 읽기 불가 경로는 root 로 재확인")
R["U-38"] = lines_rule("U-38", "DoS 취약 서비스 비활성화(echo/discard/daytime/chargen)", "상",
                       svc_cmd(["echo", "discard", "daytime", "chargen"], []),
                       note="echo/discard/daytime/chargen(inetd/xinetd) 활성이면 취약")
R["U-39"] = lines_rule("U-39", "불필요한 NFS 서비스 비활성화", "상",
                       svc_cmd(["nfs-server", "nfs"], ["nfsd", "rpc.mountd", "mountd", "biod", "rpc.nfsd"]),
                       note="NFS 데몬 활성이면 취약(운영상 필요 시 예외 사유 기록)")
R["U-40"] = rule(
    "U-40", "NFS 접근 통제", "상",
    [dict(key="nfs", cmd=svc_cmd(["nfs-server"], ["nfsd", "rpc.mountd", "mountd"])),
     dict(key="exports", cmd="grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports 2>/dev/null"),
     dict(key="open", cmd="grep -vE '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -E '\\*|no_root_squash|^[[:space:]]*[^[:space:]]+[[:space:]]*$'")],
    [{"when": {"nfs": {"absent": True}}, "then": "NA"},
     {"when": {"exports": {"absent": True}}, "then": "NA"},
     {"when": {"open": {"exists": True}}, "then": "VULN"},
     {"else": "GOOD"}],
    ["exports"], note="NFS 미사용 N/A. exports 에 호스트 제한 없음/'*'/no_root_squash 있으면 취약")
R["U-41"] = lines_rule("U-41", "불필요한 automountd 제거", "상",
                       svc_cmd(["autofs"], ["automount", "automountd", "autofs"]), note="automount 활성이면 취약")
_rpc = ["rstatd", "rusersd", "rwalld", "sprayd", "pcnfsd", "rquotad", "ttdbserver", "cmsd",
        "rpc.rstatd", "rpc.rusersd", "rpc.rwalld", "rpc.sprayd", "rpc.pcnfsd", "rpc.rquotad",
        "rpc.ttdbserverd", "rpc.cmsd", "kcms_server", "cachefsd"]
R["U-42"] = lines_rule("U-42", "불필요한 RPC 서비스 비활성화", "상",
                       svc_cmd(["rstatd", "rusersd", "rwalld", "sprayd", "pcnfsd", "rquotad", "ttdbserver", "cmsd"], _rpc),
                       note="rstatd/rusersd/rwalld/sprayd/pcnfsd/rquotad/ttdbserver/cmsd 활성이면 취약")
R["U-43"] = lines_rule("U-43", "NIS, NIS+ 점검", "상",
                       svc_cmd(["ypserv", "ypbind"], ["ypserv", "ypbind", "ypxfrd", "rpc.yppasswdd", "rpc.ypupdated", "nisd"]),
                       note="NIS/NIS+ 데몬 활성이면 취약(NIS+ 또는 LDAP 권고)")
R["U-44"] = lines_rule("U-44", "tftp, talk 서비스 비활성화", "상",
                       svc_cmd(["tftp", "talk", "ntalk"], ["tftpd", "in.tftpd", "talkd", "in.talkd", "ntalkd", "in.ntalkd", "atftpd"]),
                       note="tftp/talk/ntalk 활성이면 취약")

_mta = "ps -e -o comm= 2>/dev/null | grep -xE '(sendmail|postfix|master|exim4?|qmail-send|smtpd)' | sort -u"
_mta_ver = ("(command -v postconf >/dev/null && postconf -h mail_version 2>/dev/null | sed 's/^/postfix /'); "
            "(command -v sendmail >/dev/null && sendmail -d0.1 -bv root 2>/dev/null < /dev/null | grep -i version | head -1); "
            "(command -v exim >/dev/null && exim --version 2>/dev/null | head -1)")
_privacy = "grep -hiE '^[[:space:]]*O[[:space:]]*PrivacyOptions' /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
R["U-45"] = rule("U-45", "메일 서비스 버전 점검", "상",
                 [dict(key="mta", cmd=_mta), dict(key="ver", cmd=_mta_ver, timeout=30)],
                 [{"when": {"mta": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}],
                 ["mta", "ver"], note="MTA 미구동 N/A. 구동 시 버전을 벤더 취약점 공지와 대조(수동)")
R["U-46"] = rule(
    "U-46", "일반 사용자의 메일 서비스 실행 방지", "상",
    [dict(key="mta", cmd=_mta), dict(key="sm", cmd="ps -e -o comm= 2>/dev/null | grep -x sendmail"),
     dict(key="priv", cmd=_privacy)],
    [{"when": {"mta": {"absent": True}}, "then": "NA"},
     {"when": {"sm": {"absent": True}}, "then": "NA"},
     {"when": {"priv": {"regex": r"(?i)restrictqrun"}}, "then": "GOOD"},
     {"when": {"priv": {"exists": True}}, "then": "VULN"},
     {"else": "MANUAL"}],
    ["mta", "priv"], note="sendmail: PrivacyOptions 에 restrictqrun 있어야 양호. postfix/exim 은 해당 없음(N/A)")
R["U-47"] = rule(
    "U-47", "스팸 메일 릴레이 제한", "상",
    [dict(key="mta", cmd=_mta),
     dict(key="cfg", cmd="(command -v postconf >/dev/null && postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>/dev/null); "
                         "grep -hiE 'promiscuous_relay|relay_entire_domain' /etc/mail/sendmail.mc /etc/mail/sendmail.cf 2>/dev/null | head -5; "
                         "ls -l /etc/mail/access* 2>/dev/null", timeout=30)],
    [{"when": {"mta": {"absent": True}}, "then": "NA"},
     {"when": {"cfg": {"regex": r"(?i)promiscuous_relay|relay_entire_domain"}}, "then": "VULN"},
     {"when": {"cfg": {"regex": r"reject_unauth_destination|permit_mynetworks"}}, "then": "GOOD"},
     {"else": "MANUAL"}],
    ["mta", "cfg"], note="postfix reject_unauth_destination / sendmail access DB 로 릴레이 제한. promiscuous_relay 는 취약")
R["U-48"] = rule(
    "U-48", "expn, vrfy 명령어 제한", "중",
    [dict(key="mta", cmd=_mta), dict(key="priv", cmd=_privacy),
     dict(key="pf", cmd="command -v postconf >/dev/null && postconf -h disable_vrfy_command 2>/dev/null")],
    [{"when": {"mta": {"absent": True}}, "then": "NA"},
     {"when": {"priv": {"regex": r"(?i)goaway|(noexpn.*novrfy|novrfy.*noexpn)"}}, "then": "GOOD"},
     {"when": {"priv": {"exists": True}}, "then": "VULN"},
     {"when": {"pf": {"eq": "yes"}}, "then": "GOOD"},
     {"when": {"pf": {"eq": "no"}}, "then": "VULN"},
     {"else": "MANUAL"}],
    ["mta", "priv", "pf"], note="sendmail PrivacyOptions noexpn,novrfy(또는 goaway) / postfix disable_vrfy_command=yes 이면 양호")

_named = "ps -e -o comm= 2>/dev/null | grep -xE '(named|named-pkcs11|bind9)' | sort -u"
_named_conf = ("cat /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null "
               "| grep -vE '^[[:space:]]*(//|#)'")
R["U-49"] = rule("U-49", "DNS 보안 버전 패치", "상",
                 [dict(key="named", cmd=_named), dict(key="ver", cmd="named -v 2>/dev/null | head -1")],
                 [{"when": {"named": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}],
                 ["named", "ver"], note="BIND 미구동 N/A. 구동 시 버전을 ISC 공지와 대조(수동)")
R["U-50"] = rule(
    "U-50", "DNS Zone Transfer 설정", "상",
    [dict(key="named", cmd=_named), dict(key="xfer", cmd=_named_conf + " | grep -iE 'allow-transfer' | head -5")],
    [{"when": {"named": {"absent": True}}, "then": "NA"},
     {"when": {"xfer": {"regex": r"(?i)allow-transfer\s*\{\s*any"}}, "then": "VULN"},
     {"when": {"xfer": {"exists": True}}, "then": "GOOD"},
     {"else": "VULN"}],
    ["named", "xfer"], note="allow-transfer 로 전송 대상을 제한해야 양호. 미설정/any 취약")
R["U-51"] = rule(
    "U-51", "DNS 서비스의 취약한 동적 업데이트 설정 금지", "중",
    [dict(key="named", cmd=_named), dict(key="upd", cmd=_named_conf + " | grep -iE 'allow-update' | head -5")],
    [{"when": {"named": {"absent": True}}, "then": "NA"},
     {"when": {"upd": {"regex": r"(?i)allow-update\s*\{\s*any"}}, "then": "VULN"},
     {"else": "GOOD"}],
    ["named", "upd"], note="allow-update { any; } 이면 취약. 미설정(기본 none)·제한 설정은 양호")
R["U-52"] = lines_rule("U-52", "Telnet 서비스 비활성화", "중", svc_cmd(["telnet"], ["telnetd", "in.telnetd"]),
                       note="telnet 활성이면 취약(SSH 사용)")

_ftp = svc_cmd(["ftp"], ["vsftpd", "proftpd", "pure-ftpd", "in.ftpd", "ftpd", "wu-ftpd"])
R["U-53"] = rule(
    "U-53", "FTP 서비스 정보 노출 제한", "하",
    [dict(key="ftp", cmd=_ftp),
     dict(key="banner", cmd="grep -hiE '^[[:space:]]*(ftpd_banner|ServerIdent|banner_file)' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf "
                            "/etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null")],
    [{"when": {"ftp": {"absent": True}}, "then": "NA"},
     {"when": {"banner": {"exists": True}}, "then": "MANUAL"},
     {"else": "VULN"}],
    ["ftp", "banner"], note="FTP 미구동 N/A. 배너 설정 없으면 버전 노출(취약), 있으면 내용 확인")
R["U-54"] = lines_rule("U-54", "암호화되지 않는 FTP 서비스 비활성화", "중", _ftp, note="평문 FTP 활성이면 취약(SFTP/FTPS 권고)")
R["U-55"] = rule(
    "U-55", "FTP 계정 Shell 제한", "중",
    [dict(key="acct", cmd="grep -E '^ftp:' /etc/passwd 2>/dev/null")],
    [{"when": {"acct": {"absent": True}}, "then": "NA"},
     {"when": {"acct": {"regex": r"(nologin|/bin/false)\s*$"}}, "then": "GOOD"},
     {"else": "VULN"}],
    ["acct"], note="ftp 계정 셸이 /sbin/nologin 또는 /bin/false 여야 양호")
R["U-56"] = rule(
    "U-56", "FTP 서비스 접근 제어 설정", "하",
    [dict(key="ftp", cmd=_ftp),
     dict(key="acl", cmd="grep -hE 'ftp|vsftpd|proftpd' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; "
                         "grep -hiE '^[[:space:]]*(tcp_wrappers|<Limit LOGIN>|Allow from|Deny from)' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf "
                         "/etc/proftpd/proftpd.conf 2>/dev/null; ls -l /etc/ftpaccess 2>/dev/null")],
    [{"when": {"ftp": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}],
    ["ftp", "acl"], note="FTP 구동 시 접근제어(tcp_wrappers/Limit/ftpaccess) 설정 적정성 확인")
R["U-57"] = rule(
    "U-57", "Ftpusers 파일 설정", "중",
    [dict(key="ftp", cmd=_ftp),
     dict(key="deny", cmd="grep -hE '^root$' /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list "
                          "/etc/vsftpd.user_list /etc/proftpd/ftpusers 2>/dev/null | head -1"),
     dict(key="ls", cmd="ls -l /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list 2>/dev/null")],
    [{"when": {"ftp": {"absent": True}}, "then": "NA"},
     {"when": {"deny": {"exists": True}}, "then": "GOOD"},
     {"else": "VULN"}],
    ["ftp", "ls"], note="ftpusers(접속 금지 목록)에 root 가 있어야 양호")

_snmp = svc_cmd(["snmpd"], ["snmpd", "snmpdv3ne", "snmpdv1"])
_snmpconf = "grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf 2>/dev/null"
_community = _snmpconf + " | grep -iE '^[[:space:]]*(r[ow]community6?|com2sec|community)[[:space:]]'"
R["U-58"] = lines_rule("U-58", "불필요한 SNMP 서비스 구동 점검", "중", _snmp, note="snmpd 구동이면 취약(운영상 필요 시 예외 사유 기록)")
R["U-59"] = rule(
    "U-59", "안전한 SNMP 버전 사용", "상",
    [dict(key="snmp", cmd=_snmp), dict(key="v12", cmd=_community),
     dict(key="v3", cmd=_snmpconf + " | grep -iE '^[[:space:]]*(r[ow]user|createUser|usm)'")],
    [{"when": {"snmp": {"absent": True}}, "then": "NA"},
     {"when": {"v12": {"exists": True}}, "then": "VULN"},
     {"when": {"v3": {"exists": True}}, "then": "GOOD"},
     {"else": "MANUAL"}],
    ["v12", "v3"], note="v1/v2c(community) 설정 있으면 취약, v3(USM) 만 있으면 양호")
R["U-60"] = rule(
    "U-60", "SNMP Community String 복잡성 설정", "중",
    [dict(key="snmp", cmd=_snmp), dict(key="com", cmd=_community)],
    [{"when": {"snmp": {"absent": True}}, "then": "NA"},
     {"when": {"com": {"absent": True}}, "then": "NA"},
     {"when": {"com": {"regex": r"(?i)\s(public|private)(\s|$)"}}, "then": "VULN"},
     {"else": "MANUAL"}],
    ["com"], note="커뮤니티 문자열이 public/private 이면 취약. 그 외는 복잡성(길이·문자조합) 수동확인")
R["U-61"] = rule(
    "U-61", "SNMP Access Control 설정", "상",
    [dict(key="snmp", cmd=_snmp), dict(key="com", cmd=_snmpconf + " | grep -iE '^[[:space:]]*(r[ow]community6?|com2sec)[[:space:]]'")],
    [{"when": {"snmp": {"absent": True}}, "then": "NA"},
     {"when": {"com": {"absent": True}}, "then": "NA"},
     {"when": {"com": {"regex": r"(?im)^\s*r[ow]community6?\s+\S+\s*$|\sdefault(\s|$)"}}, "then": "VULN"},
     {"else": "GOOD"}],
    ["com"], note="ro/rw 커뮤니티 설정에 접근 허용 소스(IP/네트워크)가 없거나 default 면 취약")
R["U-62"] = rule(
    "U-62", "로그인 시 경고 메시지 설정", "하",
    [dict(key="banners", cmd="for f in /etc/issue /etc/issue.net /etc/motd; do [ -s $f ] && grep -vE '^[[:space:]]*$' $f | head -3 | sed \"s#^#$f: #\"; done"),
     dict(key="sshb", cmd="grep -hiE '^[[:space:]]*Banner' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null")],
    # 배포판 기본 배너(OS명·\n \l 같은 getty 이스케이프만)는 경고문이 아니다. 문자열 안의 \\n 은 정규식의 '역슬래시+n' 리터럴.
    [{"when": {"banners": {"regex": r"(?im)^/etc/(issue|issue\.net|motd): .*(\\n \\l|Kernel \\r on an \\m|Welcome to \S+)|^/etc/\S+: (Ubuntu|Debian|CentOS|Red Hat|Rocky|AlmaLinux|SUSE)[^\n]*$"},
               "sshb": {"absent": True}}, "then": "VULN"},
     {"when": {"banners": {"exists": True}}, "then": "GOOD"},
     {"when": {"sshb": {"regex": r"(?i)Banner\s+/"}}, "then": "GOOD"},
     {"else": "VULN"}],
    ["banners", "sshb"], note="/etc/issue(.net)·/etc/motd 또는 sshd Banner 에 경고문이 있어야 양호")
R["U-63"] = rule(
    "U-63", "sudo 명령어 접근 관리", "중",
    [dict(key="ls", cmd="ls -l /etc/sudoers 2>/dev/null; ls -ld /etc/sudoers.d 2>/dev/null"),
     dict(key="perm", cmd="find /etc/sudoers /etc/sudoers.d -maxdepth 1 -type f \\( -perm -o+r -o -perm -o+w -o -perm -g+w -o ! -user root \\) 2>/dev/null"),
     dict(key="grants", cmd="grep -hE '^[[:space:]]*[^#[:space:]].*ALL[[:space:]]*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -20")],
    [{"when": {"ls": {"absent": True}}, "then": "NA"},
     {"when": {"perm": {"exists": True}}, "then": "VULN"},
     {"else": "MANUAL"}],
    ["ls", "grants"], note="sudoers 는 root 소유 440. ALL 권한/NOPASSWD 부여 계정은 필요성 확인(수동). 읽기 불가 시 수동")
R["U-65"] = rule(
    "U-65", "NTP 및 시각 동기화 설정", "중",
    [dict(key="ntp", cmd="ps -e -o comm= 2>/dev/null | grep -xE '(chronyd|ntpd|xntpd|systemd-timesyn|systemd-timesyncd|openntpd)' | sort -u; "
                         "systemctl is-active chronyd ntpd systemd-timesyncd 2>/dev/null | grep -x active | sed 's/^/systemd: /'; "
                         "timedatectl 2>/dev/null | grep -iE 'NTP (service|synchronized)|synchronized'"),
     dict(key="src", cmd="grep -hE '^[[:space:]]*(server|pool|peer)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf /etc/ntp.conf 2>/dev/null | head -5; "
                         "grep -hE '^[[:space:]]*NTP=' /etc/systemd/timesyncd.conf 2>/dev/null")],
    [{"when": {"ntp": {"regex": r"(?i)chronyd|ntpd|timesync|active|yes"}}, "then": "GOOD"}, {"else": "VULN"}],
    ["ntp", "src"], note="chronyd/ntpd/systemd-timesyncd 가 동작하고 동기화 서버가 있어야 양호", cat="로그관리")
R["U-66"] = rule(
    "U-66", "정책에 따른 시스템 로깅 설정", "중",
    [dict(key="daemon", cmd="ps -e -o comm= 2>/dev/null | grep -xE '(rsyslogd|syslogd|syslog-ng|systemd-journal|systemd-journald)' | sort -u"),
     dict(key="conf", cmd="grep -hvE '^[[:space:]]*(#|\\$)|^[[:space:]]*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -20")],
    [{"when": {"daemon": {"absent": True}}, "then": "VULN"},
     {"when": {"conf": {"regex": r"auth|authpriv|\\*\\.(info|notice|warn|err|crit|alert|emerg|\\*)"}}, "then": "GOOD"},
     {"else": "MANUAL"}],
    ["daemon", "conf"], note="syslog 계열 데몬 동작 + auth/authpriv 등 정책 항목이 설정돼야 양호. journald 단독은 보관 정책 확인", cat="로그관리")
R["U-67"] = lines_rule(
    "U-67", "로그 디렉터리 소유자 및 권한 설정", "중",
    "find /var/log /var/adm /var/log/audit -maxdepth 0 ! -user root 2>/dev/null; "
    "find /var/log /var/adm /var/log/audit -maxdepth 1 ! -type l -perm -o+w ! -name wtmp ! -name btmp ! -name lastlog 2>/dev/null | head -30",
    extra_collect=[dict(key="ls", cmd="ls -ld /var/log /var/adm 2>/dev/null")], evidence=["ls", "found"],
    note="로그 디렉터리/파일이 root 소유이고 other 쓰기 없음이어야 양호(wtmp/btmp/lastlog 제외)", cat="로그관리")


def main() -> int:
    from infraguard.rules.declarative import load_file
    for rid, spec in R.items():
        header = f"# {rid} {spec['name']} — 선언형 룰(gen_rules_services.py 생성). 명령은 상수, 판정은 화이트리스트 연산자만.\n"
        (D / f"{rid}.yaml").write_text(header + yaml.safe_dump(spec, allow_unicode=True, sort_keys=False, width=220),
                                       encoding="utf-8", newline="\n")
    ok = all(load_file(D / f"{r}.yaml").id == r for r in R)
    print(f"written {len(R)} rules | all load: {ok} | total yaml: {len(list(D.glob('*.yaml')))}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
