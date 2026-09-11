"""네트워크 장비(Cisco IOS) 선언형 룰 생성기 — N-01~N-38 (KISA 2026 V장). show 명령만.

    python scripts/gen_rules_netdev.py [rulepacks/kisa-2026/rules]

shell: raw — transport.netdev 가 장비 셸에 한 줄씩 보낸다. `show running-config` 는 세션 캐시라 38룰이 한 번만 받는다.
Cisco IOS 기본값이 확실한 항목은 설정 부재를 기본값으로 판정하고 note 에 남긴다. Junos 는 각 룰의 variants 블록(set 문법 정규식).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

PLAT = ["cisco-ios"]
ACC, PERM, PATCH, LOG, FUNC = "계정관리", "접근관리", "패치관리", "로그관리", "기능관리"
CFG = {"key": "cfg", "cmd": "show running-config", "timeout": 60}


def rule(rid: str, name: str, sev: str, cat: str, verdict: list[dict], *, collect: list[dict] | None = None,
         extract: list[dict] | None = None, note: str = "", manual: bool = False, evidence: list[str] | None = None) -> dict:
    d: dict = {"id": rid, "name": name, "severity": sev, "category": cat, "platforms": PLAT, "shell": "raw"}
    if manual:
        d["manual"] = True
    d["collect"] = collect or [CFG]
    if extract:
        d["extract"] = extract
    d["verdict"] = verdict
    d["evidence"] = evidence if evidence is not None else [c["key"] for c in d["collect"]]
    if note:
        d["note"] = note
    return d


def has(pat: str) -> dict:
    return {"cfg": {"regex": pat}}


def grep(key: str, pat: str) -> dict:
    """설정에서 관련 줄만 근거로 뽑는다(전체 running-config 를 증적에 넣지 않게)."""
    return {"key": key, "cmd": f"show running-config | include {pat}", "timeout": 60}


VTY_BLOCK = r"(?ms)^line vty.*?(?=^line |^!|\Z)"


# ------------------------------------------------------------------ Junos variant
# `show configuration | display set` 의 set 문법을 본다. 근거는 `| match` 로 관련 줄만.
JCFG = {"key": "cfg", "cmd": "show configuration | display set", "timeout": 60}


def jhas(pat: str) -> dict:
    return {"cfg": {"regex": pat}}


def jgrep(pat: str) -> dict:
    return {"key": "ev", "cmd": f'show configuration | display set | match "{pat}"', "timeout": 60}


def jv(verdict: list[dict], *, grep: str | None = None, collect: list[dict] | None = None,
       extract: list[dict] | None = None, note: str = "") -> dict:
    col = collect or ([JCFG, jgrep(grep)] if grep else [JCFG])
    d: dict = {"platforms": ["junos"], "shell": "raw", "collect": col, "verdict": verdict,
               "evidence": ["ev"] if grep else [c["key"] for c in col]}
    if extract:
        d["extract"] = extract
    if note:
        d["note"] = note
    return d


JUNOS: dict[str, dict] = {
    "N-01": jv([{"when": jhas(r"(?m)^set system root-authentication encrypted-password"), "then": "GOOD"}, {"else": "VULN"}],
               grep="root-authentication|system login user", note="root 비밀번호(encrypted-password)가 설정돼 있어야 양호"),
    "N-02": jv([{"when": {"n": {"ge": 8}}, "then": "GOOD"}, {"else": "MANUAL"}], grep="login password",
               extract=[{"from": "cfg", "regex": r"(?m)^set system login password minimum-length (?P<n>\d+)"}],
               note="system login password minimum-length 8 이상"),
    "N-03": jv([{"when": jhas(r"(?m)^set system root-authentication encrypted-password"), "then": "GOOD"}, {"else": "VULN"}],
               grep="encrypted-password|plain-text", note="Junos 는 비밀번호를 항상 해시 저장(encrypted-password)"),
    "N-04": jv([{"when": {"n": {"le": 5}}, "then": "GOOD"}, {"else": "VULN"}], grep="retry-options",
               extract=[{"from": "cfg", "regex": r"(?m)^set system login retry-options tries-before-disconnect (?P<n>\d+)"}],
               note="login retry-options tries-before-disconnect 5 이하(미설정 기본 10 → 취약)"),
    "N-05": jv([{"else": "MANUAL"}], grep="system login user|system login class"),
    "N-06": jv([{"when": jhas(r"(?m)^set interfaces lo0 unit 0 family inet filter input"), "then": "GOOD"}, {"else": "VULN"}],
               grep="lo0 unit 0 family inet filter", note="lo0 입력 필터로 관리 접근 제한"),
    "N-07": jv([{"when": {"m": {"le": 10}}, "then": "GOOD"}, {"else": "VULN"}], grep="idle-timeout",
               extract=[{"from": "cfg", "regex": r"(?m)^set system login class \S+ idle-timeout (?P<m>\d+)"}],
               note="login class idle-timeout 10분 이하(미설정 → 무제한, 취약)"),
    "N-08": jv([{"when": jhas(r"(?m)^set system services telnet"), "then": "VULN"},
                {"when": jhas(r"(?m)^set system services ssh"), "then": "GOOD"}, {"else": "MANUAL"}],
               grep="system services (ssh|telnet)"),
    "N-09": jv([{"when": jhas(r"(?m)^set system ports auxiliary disable"), "then": "GOOD"}, {"else": "MANUAL"}],
               grep="system ports"),
    "N-10": jv([{"when": jhas(r"(?m)^set system login (message|announcement)"), "then": "GOOD"}, {"else": "VULN"}],
               grep="login message|login announcement"),
    "N-11": jv([{"when": jhas(r"(?m)^set system syslog host \S+"), "then": "GOOD"}, {"else": "VULN"}], grep="syslog host"),
    "N-12": jv([{"else": "MANUAL"}], collect=[{"key": "ver", "cmd": "show version", "timeout": 30}]),
    "N-13": jv([{"when": jhas(r"(?m)^set system syslog (file|archive)"), "then": "MANUAL"}, {"else": "VULN"}],
               grep="syslog (file|archive)", note="syslog 파일·archive size 설정을 로그량과 대조"),
    "N-14": jv([{"when": jhas(r"(?m)^set system syslog"), "then": "MANUAL"}, {"else": "VULN"}], grep="syslog"),
    "N-15": jv([{"when": jhas(r"(?m)^set system ntp server"), "then": "GOOD"}, {"else": "VULN"}], grep="ntp"),
    "N-16": jv([{"else": "GOOD"}], grep="syslog time-format", note="Junos syslog 는 기본 타임스탬프 포함"),
    "N-17": jv([{"when": jhas(r"(?m)^set snmp community"), "then": "MANUAL"}, {"else": "GOOD"}], grep="^set snmp"),
    "N-18": jv([{"when": jhas(r"(?mi)^set snmp community (public|private)\b"), "then": "VULN"},
                {"when": jhas(r"(?m)^set snmp community (?=\S{8,})(?=\S*[A-Za-z])(?=\S*\d)(?=\S*[^A-Za-z0-9\s])\S+"), "then": "GOOD"},
                {"when": jhas(r"(?m)^set snmp community"), "then": "VULN"}, {"else": "GOOD"}], grep="snmp community"),
    "N-19": jv([{"when": jhas(r"(?m)^set snmp community \S+ clients"), "then": "GOOD"},
                {"when": jhas(r"(?m)^set snmp community"), "then": "VULN"}, {"else": "GOOD"}], grep="snmp community"),
    "N-20": jv([{"when": jhas(r"(?m)^set snmp community \S+ authorization read-write"), "then": "VULN"}, {"else": "GOOD"}],
               grep="snmp community"),
    "N-21": jv([{"when": jhas(r"(?m)^set system services (tftp|ftp)"), "then": "VULN"}, {"else": "GOOD"}], grep="services (tftp|ftp)"),
    "N-22": jv([{"when": jhas(r"(?m)rpf-check"), "then": "GOOD"}, {"else": "MANUAL"}], grep="rpf-check|firewall filter"),
    "N-23": jv([{"else": "MANUAL"}], grep="firewall|policer|screen"),
    "N-24": jv([{"when": {"br": {"regex": r"(?m)^\S+\s+up\s+down\b"}}, "then": "VULN"},
                {"when": {"br": {"exists": True}}, "then": "GOOD"}, {"else": "MANUAL"}],
               collect=[{"key": "br", "cmd": "show interfaces terse", "timeout": 30}],
               note="Admin up 인데 Link down 인 물리 인터페이스가 있으면 취약(미사용은 disable)"),
    "N-25": jv([{"when": jhas(r"(?m)^set system services ssh client-alive-interval"), "then": "GOOD"}, {"else": "VULN"}],
               grep="client-alive"),
    "N-26": jv([{"when": jhas(r"(?m)^set system services finger"), "then": "VULN"}, {"else": "GOOD"}], grep="finger"),
    "N-27": jv([{"when": jhas(r"(?m)^set system services web-management"), "then": "VULN"}, {"else": "GOOD"}], grep="web-management"),
    "N-28": jv([{"else": "GOOD"}], grep="services", note="Junos 에는 TCP/UDP small servers 가 없다"),
    "N-29": jv([{"when": jhas(r"(?m)^set forwarding-options helpers bootp"), "then": "VULN"}, {"else": "GOOD"}], grep="bootp|dhcp"),
    "N-30": jv([{"when": jhas(r"(?m)^set protocols lldp interface all"), "then": "VULN"},
                {"when": jhas(r"(?m)^set protocols lldp"), "then": "MANUAL"}, {"else": "GOOD"}], grep="lldp", note="CDP 상당 = LLDP"),
    "N-31": jv([{"when": jhas(r"(?m)targeted-broadcast"), "then": "VULN"}, {"else": "GOOD"}], grep="targeted-broadcast"),
    "N-32": jv([{"when": jhas(r"(?m)no-source-route"), "then": "GOOD"}, {"else": "MANUAL"}], grep="source-route",
               note="Junos 기본 동작을 장비 문서로 확인 — no-source-route 설정이 있으면 양호"),
    "N-33": jv([{"when": jhas(r"(?m)proxy-arp"), "then": "VULN"}, {"else": "GOOD"}], grep="proxy-arp"),
    "N-34": jv([{"when": jhas(r"(?m)^set system no-redirects"), "then": "GOOD"}, {"else": "VULN"}], grep="redirects|unreachable"),
    "N-35": jv([{"else": "GOOD"}], grep="ident", note="Junos 에 identd 없음"),
    "N-36": jv([{"when": jhas(r"(?m)^set system name-server"), "then": "MANUAL"}, {"else": "GOOD"}], grep="name-server"),
    "N-37": jv([{"else": "GOOD"}], grep="pad", note="Junos 에 PAD 서비스 없음"),
    "N-38": jv([{"else": "GOOD"}], grep="mask-reply", note="Junos 에 mask-reply 없음"),
}


RULES: list[dict] = [
    rule("N-01", "비밀번호 설정", "상", ACC,
         [{"when": has(r"(?m)^enable secret"), "then": "GOOD"}, {"when": has(r"(?m)^enable password"), "then": "MANUAL"},
          {"else": "VULN"}], collect=[CFG, grep("ev", "^enable|^username|^ line|^line")], evidence=["ev"],
         note="enable secret 이면 양호. enable password 만 있으면 기본값 변경 여부 확인"),
    rule("N-02", "비밀번호 복잡성 설정", "상", ACC,
         [{"when": {"n": {"ge": 8}}, "then": "GOOD"}, {"else": "MANUAL"}],
         collect=[CFG, grep("ev", "passwords min-length|aaa")], evidence=["ev"],
         extract=[{"from": "cfg", "regex": r"(?m)^security passwords min-length (?P<n>\d+)"}],
         note="security passwords min-length 8 이상이면 양호, 없으면 기관 정책으로 판단"),
    rule("N-03", "암호화된 비밀번호 사용", "상", ACC,
         [{"when": {"cfg": {"regex": r"(?ms)(?=.*^service password-encryption)(?=.*^enable secret)"}}, "then": "GOOD"},
          {"else": "VULN"}], collect=[CFG, grep("ev", "password-encryption|^enable")], evidence=["ev"],
         note="service password-encryption + enable secret"),
    rule("N-04", "계정 잠금 임계값 설정", "상", ACC,
         [{"when": {"n": {"le": 5}}, "then": "GOOD"}, {"when": {"m": {"le": 5}}, "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "login block-for|max-fail")], evidence=["ev"],
         extract=[{"from": "cfg", "regex": r"(?m)^login block-for \d+ attempts (?P<n>\d+)"},
                  {"from": "cfg", "regex": r"(?m)^aaa local authentication attempts max-fail (?P<m>\d+)"}],
         note="login block-for … attempts N 또는 aaa local authentication attempts max-fail N, N≤5"),
    rule("N-05", "사용자·명령어별 권한 설정", "중", ACC, [{"else": "MANUAL"}], manual=True,
         collect=[CFG, grep("ev", "^username|^privilege")], evidence=["ev"], note="계정별 privilege 레벨을 보고 업무 적합성 판단"),
    rule("N-06", "VTY 접근(ACL) 설정", "상", PERM,
         [{"when": {"vty": {"regex": r"access-class"}}, "then": "GOOD"}, {"when": {"vty": {"exists": True}}, "then": "VULN"},
          {"else": "MANUAL"}], extract=[{"from": "cfg", "regex": r"(?s)(?P<vty>" + VTY_BLOCK[5:] + ")"}]),
    rule("N-07", "Session Timeout 설정", "상", PERM,
         [{"when": {"vty": {"regex": r"exec-timeout 0 0"}}, "then": "VULN"},
          {"when": {"vty": {"regex": r"exec-timeout (?:1[1-9]|[2-9]\d|\d{3,}) "}}, "then": "VULN"},
          {"when": {"vty": {"exists": True}}, "then": "GOOD"}, {"else": "MANUAL"}],
         extract=[{"from": "cfg", "regex": r"(?s)(?P<vty>" + VTY_BLOCK[5:] + ")"}],
         note="기준 10분 이하. 설정 없음 = IOS 기본 10분(양호), exec-timeout 0 0 은 무제한(취약)"),
    rule("N-08", "VTY 접속 시 안전한 프로토콜 사용", "중", PERM,
         [{"when": {"vty": {"regex": r"transport input (telnet|all)"}}, "then": "VULN"},
          {"when": {"vty": {"regex": r"transport input ssh"}}, "then": "GOOD"},
          {"when": {"vty": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}],
         extract=[{"from": "cfg", "regex": r"(?s)(?P<vty>" + VTY_BLOCK[5:] + ")"}], note="transport input ssh 만 허용. 미설정은 기본 all/telnet"),
    rule("N-09", "불필요한 보조 입출력 포트 사용 금지", "중", PERM,
         [{"when": {"aux": {"regex": r"no exec|transport input none"}}, "then": "GOOD"},
          {"when": {"aux": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}],
         extract=[{"from": "cfg", "regex": r"(?s)(?P<aux>^line aux.*?(?=^line |^!|\Z))"}], note="line aux 에 no exec 또는 transport input none"),
    rule("N-10", "로그인 시 경고 메시지 설정", "중", PERM,
         [{"when": has(r"(?m)^banner (login|motd)"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "^banner")], evidence=["ev"]),
    rule("N-11", "원격로그 서버 사용", "중", PATCH,
         [{"when": has(r"(?m)^logging (host )?\d+\.\d+\.\d+\.\d+"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "^logging")], evidence=["ev"]),
    rule("N-12", "주기적 보안 패치 및 벤더 권고사항 적용", "상", PATCH, [{"else": "MANUAL"}], manual=True,
         collect=[{"key": "ver", "cmd": "show version", "timeout": 30}], note="IOS 버전을 Cisco 권고와 대조"),
    rule("N-13", "로깅 버퍼 크기 설정", "중", LOG,
         [{"when": {"n": {"ge": 16384}}, "then": "GOOD"}, {"when": {"n": {"exists": True}}, "then": "MANUAL"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "^logging buffered")], evidence=["ev"],
         extract=[{"from": "cfg", "regex": r"(?m)^logging buffered (?P<n>\d+)"}], note="logging buffered 16384 이상이면 양호, 작으면 로그량 대비 판단"),
    rule("N-14", "정책에 따른 로깅 설정", "중", LOG,
         [{"when": has(r"(?m)^logging (buffered|trap|host|\d)"), "then": "MANUAL"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "^logging")], evidence=["ev"], note="로깅 설정이 있으면 기관 정책과 대조, 없으면 취약"),
    rule("N-15", "NTP 및 시각 동기화 설정", "중", LOG,
         [{"when": has(r"(?m)^ntp server"), "then": "GOOD"}, {"else": "VULN"}], collect=[CFG, grep("ev", "^ntp")], evidence=["ev"]),
    rule("N-16", "Timestamp 로그 설정", "하", LOG,
         [{"when": has(r"(?m)^service timestamps log datetime"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "^service timestamps")], evidence=["ev"]),
    rule("N-17", "SNMP 서비스 확인", "상", FUNC,
         [{"when": has(r"(?m)^snmp-server community"), "then": "MANUAL"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "^snmp-server")], evidence=["ev"], note="SNMP 설정이 없으면 양호, 있으면 사용 필요성 판단"),
    rule("N-18", "SNMP Community String 복잡성 설정", "상", FUNC,
         [{"when": has(r"(?mi)^snmp-server community (public|private)\b"), "then": "VULN"},
          {"when": has(r"(?m)^snmp-server community (?=\S{8,})(?=\S*[A-Za-z])(?=\S*\d)(?=\S*[^A-Za-z0-9\s])\S+"), "then": "GOOD"},
          {"when": has(r"(?m)^snmp-server community"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "^snmp-server community")], evidence=["ev"],
         note="public/private 취약. 8자 이상·영문+숫자+특수문자면 양호"),
    rule("N-19", "SNMP ACL 설정", "상", FUNC,
         [{"when": has(r"(?m)^snmp-server community \S+ (RO|RW|view \S+ (RO|RW)) \S+"), "then": "GOOD"},
          {"when": has(r"(?m)^snmp-server community"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "^snmp-server community")], evidence=["ev"], note="community 뒤에 ACL 번호/이름이 붙어야 양호"),
    rule("N-20", "SNMP Community 권한 설정", "상", FUNC,
         [{"when": has(r"(?m)^snmp-server community \S+ (view \S+ )?RW"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "^snmp-server community")], evidence=["ev"]),
    rule("N-21", "TFTP 서비스 차단", "상", FUNC,
         [{"when": has(r"(?m)^tftp-server"), "then": "VULN"}, {"else": "GOOD"}], collect=[CFG, grep("ev", "tftp")], evidence=["ev"]),
    rule("N-22", "Spoofing 방지 필터링 적용", "상", FUNC,
         [{"when": has(r"(?m)^\s*ip verify unicast"), "then": "GOOD"},
          {"when": has(r"(?m)^\s*deny ip (10\.0\.0\.0|172\.16\.0\.0|192\.168\.0\.0|127\.0\.0\.0|0\.0\.0\.0)"), "then": "GOOD"},
          {"else": "MANUAL"}], collect=[CFG, grep("ev", "verify unicast|deny ip")], evidence=["ev"],
         note="uRPF 또는 사설/루프백 대역 deny ACL 이 있으면 양호, 없으면 경계 장비 여부로 판단"),
    rule("N-23", "DDoS 공격 방어 설정 또는 DDoS 장비 사용", "상", FUNC, [{"else": "MANUAL"}], manual=True,
         collect=[CFG, grep("ev", "tcp intercept|rate-limit|police|control-plane")], evidence=["ev"]),
    rule("N-24", "사용하지 않는 인터페이스 비활성화", "상", FUNC,
         [{"when": {"br": {"regex": r"(?mi)\s+down\s+down\s*$"}}, "then": "VULN"}, {"when": {"br": {"exists": True}}, "then": "GOOD"},
          {"else": "MANUAL"}], collect=[{"key": "br", "cmd": "show ip interface brief", "timeout": 30}],
         note="'down down'(shutdown 아닌 미사용 링크다운)이 있으면 취약. administratively down 은 양호"),
    rule("N-25", "TCP Keepalive 서비스 설정", "중", FUNC,
         [{"when": has(r"(?m)^service tcp-keepalives-in"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "keepalives")], evidence=["ev"]),
    rule("N-26", "Finger 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^(ip finger|service finger)"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "finger")], evidence=["ev"], note="IOS 12 이후 finger 기본 비활성 — 활성 설정이 없으면 양호"),
    rule("N-27", "웹 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^ip http (secure-)?server"), "then": "VULN"}, {"when": has(r"(?m)^no ip http (secure-)?server"), "then": "GOOD"},
          {"else": "MANUAL"}], collect=[CFG, grep("ev", "^ip http|^no ip http")], evidence=["ev"],
         note="ip http server 활성이면 취약(access-class 로 제한했더라도 필요성 확인)"),
    rule("N-28", "TCP/UDP small 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^service (tcp|udp)-small-servers"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "small-servers")], evidence=["ev"], note="IOS 12 이후 기본 비활성"),
    rule("N-29", "Bootp 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^no ip bootp server"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "bootp")], evidence=["ev"], note="기본 활성 → no ip bootp server 필요"),
    rule("N-30", "CDP 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^no cdp run"), "then": "GOOD"}, {"when": has(r"(?m)^\s+no cdp enable"), "then": "MANUAL"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "cdp")], evidence=["ev"], note="전역 no cdp run 양호. 인터페이스별 no cdp enable 은 범위 확인"),
    rule("N-31", "Directed-broadcast 차단", "중", FUNC,
         [{"when": has(r"(?m)^\s+ip directed-broadcast"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "directed-broadcast")], evidence=["ev"], note="IOS 12 이후 기본 비활성"),
    rule("N-32", "Source Routing 차단", "중", FUNC,
         [{"when": has(r"(?m)^no ip source-route"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "source-route")], evidence=["ev"], note="기본 활성 → no ip source-route 필요"),
    rule("N-33", "Proxy ARP 차단", "중", FUNC,
         [{"when": has(r"(?m)^\s+no ip proxy-arp"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "proxy-arp|^interface")], evidence=["ev"], note="인터페이스별 no ip proxy-arp(기본 활성)"),
    rule("N-34", "ICMP unreachable, redirect 차단", "중", FUNC,
         [{"when": {"cfg": {"regex": r"(?ms)(?=.*^\s+no ip unreachables)(?=.*^\s+no ip redirects)"}}, "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "unreachables|redirects|^interface")], evidence=["ev"]),
    rule("N-35", "identd 서비스 차단", "중", FUNC,
         [{"when": has(r"(?m)^ip identd"), "then": "VULN"}, {"else": "GOOD"}], collect=[CFG, grep("ev", "identd")], evidence=["ev"]),
    rule("N-36", "Domain Lookup 차단", "중", FUNC,
         [{"when": has(r"(?m)^no ip domain[- ]lookup"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "domain-lookup|domain lookup")], evidence=["ev"], note="기본 활성 → no ip domain-lookup 필요"),
    rule("N-37", "pad 차단", "중", FUNC,
         [{"when": has(r"(?m)^no service pad"), "then": "GOOD"}, {"else": "VULN"}],
         collect=[CFG, grep("ev", "service pad")], evidence=["ev"], note="기본 활성 → no service pad 필요"),
    rule("N-38", "mask-reply 차단", "중", FUNC,
         [{"when": has(r"(?m)^\s+ip mask-reply"), "then": "VULN"}, {"else": "GOOD"}],
         collect=[CFG, grep("ev", "mask-reply")], evidence=["ev"], note="기본 비활성"),
]


def main(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in RULES:
        if r["id"] in JUNOS:
            r["variants"] = [JUNOS[r["id"]]]
        (out_dir / f"{r['id']}.yaml").write_text(
            f"# {r['id']} {r['name']} — Cisco IOS + Junos variant 선언형 룰(show 명령 전용). 생성: scripts/gen_rules_netdev.py\n"
            + yaml.safe_dump(r, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8", newline="\n")
    print(f"{len(RULES)} rules -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rulepacks/kisa-2026/rules")))
