"""Windows 서버 선언형 룰 생성기 — W-01~W-64 (KISA 2026 II장). PowerShell 읽기전용 명령만.

    python scripts/gen_rules_windows.py [rulepacks/kisa-2026/rules]

원칙: 레지스트리·서비스·net accounts·icacls 등 조회만. secedit /export 는 파일을 쓰므로 안 쓴다 →
그 정책들(사용자 권한 할당, 익명 SID 변환 등)은 근거만 모으고 MANUAL. 기본값이 확실한 항목은 값이 없을 때
기본값으로 판정하되 note 에 남긴다. 값 없음이 애매하면 MANUAL(추측 금지).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

LSA = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
POLSYS = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
WINLOGON = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
LANMAN = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
TCPIP = r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
RDP = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
RDPTCP = RDP + r"\WinStations\RDP-Tcp"
TSPOL = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
NETLOGON = r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
SNMP = r"HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"


def reg(path: str, name: str) -> str:
    return f"(Get-ItemProperty -LiteralPath '{path}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}'"


def regs(path: str, names: list[str]) -> str:
    """여러 값을 name=value 줄로. 없으면 name= (빈 값)."""
    quoted = "','".join(names)
    return (f"$p=Get-ItemProperty -LiteralPath '{path}' -ErrorAction SilentlyContinue; "
            f"foreach($n in @('{quoted}')){{ \"$n=$($p.$n)\" }}")


def svc_running(names: list[str]) -> str:
    return (f"Get-Service -Name {','.join(names)} -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name")


def kv_extract(key: str, name: str, var: str | None = None) -> dict:
    return {"from": key, "regex": rf"(?m)^{name}=(?P<{var or name}>.*)$"}


def rule(rid: str, name: str, sev: str, cat: str, collect: list[dict], verdict: list[dict], *,
         extract: list[dict] | None = None, evidence: list[str] | None = None, note: str = "",
         manual: bool = False) -> dict:
    d: dict = {"id": rid, "name": name, "severity": sev, "category": cat, "platforms": ["windows"],
               "shell": "powershell"}
    if manual:
        d["manual"] = True
    d["collect"] = collect
    if extract:
        d["extract"] = extract
    d["verdict"] = verdict
    d["evidence"] = evidence or [c["key"] for c in collect]
    if note:
        d["note"] = note
    return d


def c(key: str, cmd: str, timeout: int = 60) -> dict:
    return {"key": key, "cmd": cmd, "timeout": timeout}


ACC, SVC, PATCH, LOG, SEC = "계정관리", "서비스관리", "패치관리", "로그관리", "보안관리"
NET_ACCOUNTS = ("net accounts | ForEach-Object { $_ }")
# net accounts 출력은 로케일마다 라벨이 다르다 — 한/영 둘 다 잡는다
_LOCK = r"(?im)^\s*(?:Lockout threshold|잠금 임계값)[^:]*:\s*(?P<lock>\S+)"
_LOCKDUR = r"(?im)^\s*(?:Lockout duration|잠금 기간)[^:]*:\s*(?P<dur>\S+)"
_LOCKWIN = r"(?im)^\s*(?:Lockout observation window|잠금 관찰 기간|다음 시간 후 잠금 수 원래대로)[^:]*:\s*(?P<win>\S+)"
_MINLEN = r"(?im)^\s*(?:Minimum password length|최소 암호 길이)[^:]*:\s*(?P<minlen>\S+)"
_MAXAGE = r"(?im)^\s*(?:Maximum password age|최대 암호 사용 기간)[^:]*:\s*(?P<maxage>\S+)"
_MINAGE = r"(?im)^\s*(?:Minimum password age|최소 암호 사용 기간)[^:]*:\s*(?P<minage>\S+)"
_HIST = r"(?im)^\s*(?:Length of password history|암호 기록 유지)[^:]*:\s*(?P<hist>\S+)"

RULES: list[dict] = [
    rule("W-01", "Administrator 계정 이름 변경 등 보안성 강화", "상", ACC,
         [c("adm", "Get-LocalUser | Where-Object {$_.SID -like '*-500'} | Select-Object -ExpandProperty Name")],
         [{"when": {"adm_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"adm": {"eq": "Administrator"}}, "then": "VULN"},
          {"when": {"adm": {"exists": True}}, "then": "GOOD"},
          {"else": "MANUAL"}],
         note="RID 500 계정명이 Administrator 그대로면 취약. 비밀번호 강도는 별도 확인"),
    rule("W-02", "Guest 계정 비활성화", "상", ACC,
         [c("g", "(Get-LocalUser | Where-Object {$_.SID -like '*-501'}).Enabled")],
         [{"when": {"g": {"eq": "False"}}, "then": "GOOD"}, {"when": {"g": {"eq": "True"}}, "then": "VULN"},
          {"else": "MANUAL"}]),
    rule("W-03", "불필요한 계정 제거", "상", ACC,
         [c("users", "Get-LocalUser | Select-Object Name,Enabled,LastLogon,Description | Format-Table -AutoSize | Out-String -Width 200")],
         [{"else": "MANUAL"}], manual=True, note="계정 목록을 보고 퇴직·테스트 계정 여부를 분석자가 판단"),
    rule("W-04", "계정 잠금 임계값 설정", "상", ACC, [c("acc", NET_ACCOUNTS)],
         [{"when": {"lock": {"regex": r"^(?:Never|안|없음)"}}, "then": "VULN"},
          {"when": {"lock": {"le": 5}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "acc", "regex": _LOCK, "missing": "MANUAL"}], note="기준: 잠금 임계값 5 이하"),
    rule("W-05", "해독 가능한 암호화를 사용하여 암호 저장 해제", "상", ACC, [c("acc", NET_ACCOUNTS)],
         [{"else": "MANUAL"}], manual=True,
         note="ClearTextPassword 정책은 secedit 내보내기(파일 생성) 없이 읽을 수 없어 로컬 보안 정책에서 직접 확인"),
    rule("W-06", "관리자 그룹에 최소한의 사용자 포함", "상", ACC,
         [c("adm", "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object -ExpandProperty Name")],
         [{"when": {"adm_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"n": {"le": 1}}, "then": "GOOD"}, {"else": "MANUAL"}],
         extract=[{"from": "adm", "lines": "n"}], note="Administrators 구성원 1명 이하면 양호, 그 이상은 필요성 판단"),
    rule("W-07", "Everyone 사용 권한을 익명 사용자에 적용", "중", ACC, [c("v", reg(LSA, "EveryoneIncludesAnonymous"))],
         [{"when": {"v": {"eq": "1"}}, "then": "VULN"}, {"else": "GOOD"}], note="값 없음 = 기본값 0(사용 안 함)"),
    rule("W-08", "계정 잠금 기간 설정", "중", ACC, [c("acc", NET_ACCOUNTS)],
         [{"when": {"dur": {"ge": 60}, "win": {"ge": 60}}, "then": "GOOD"},
          {"when": {"dur": {"ge": 60}}, "then": "MANUAL"}, {"else": "VULN"}],
         extract=[{"from": "acc", "regex": _LOCKDUR, "missing": "MANUAL"}, {"from": "acc", "regex": _LOCKWIN}],
         note="기준: 잠금 기간·원래대로 설정 기간 60분 이상"),
    rule("W-09", "비밀번호 관리 정책 설정", "상", ACC, [c("acc", NET_ACCOUNTS)],
         [{"when": {"minlen": {"ge": 8}, "maxage": {"le": 90}, "minage": {"ge": 1}}, "then": "GOOD"},
          {"else": "VULN"}],
         extract=[{"from": "acc", "regex": _MINLEN, "missing": "MANUAL"}, {"from": "acc", "regex": _MAXAGE},
                  {"from": "acc", "regex": _MINAGE}, {"from": "acc", "regex": _HIST}],
         note="기준: 최소 길이 8, 최대 사용 90일, 최소 사용 1일. 복잡성 정책은 secedit 없이 조회 불가 → 별도 확인"),
    rule("W-10", "마지막 사용자 이름 표시 안 함", "중", ACC, [c("v", reg(POLSYS, "DontDisplayLastUserName"))],
         [{"when": {"v": {"eq": "1"}}, "then": "GOOD"}, {"else": "VULN"}]),
    rule("W-11", "로컬 로그온 허용", "중", ACC,
         [c("adm", "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object -ExpandProperty Name"),
          c("usr", "Get-LocalGroupMember -SID S-1-5-32-545 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name")],
         [{"else": "MANUAL"}], manual=True, note="SeInteractiveLogonRight 는 secedit 없이 조회 불가 — 그룹 구성원만 근거로"),
    rule("W-12", "익명 SID/이름 변환 허용 해제", "중", ACC, [c("v", reg(LSA, "TurnOffAnonymousBlock"))],
         [{"when": {"v": {"eq": "1"}}, "then": "VULN"}, {"else": "MANUAL"}], manual=True,
         note="LSAAnonymousNameLookup 은 secedit 전용. 레지스트리 TurnOffAnonymousBlock=1 이면 취약 확정, 아니면 정책 확인"),
    rule("W-13", "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한", "중", ACC, [c("v", reg(LSA, "LimitBlankPasswordUse"))],
         [{"when": {"v": {"eq": "1"}}, "then": "GOOD"}, {"when": {"v": {"eq": "0"}}, "then": "VULN"},
          {"else": "GOOD"}], note="값 없음 = 기본값 1(사용)"),
    rule("W-14", "원격터미널 접속 가능한 사용자 그룹 제한", "중", ACC,
         [c("rdu", "Get-LocalGroupMember -SID S-1-5-32-555 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"),
          c("deny", reg(RDP, "fDenyTSConnections"))],
         [{"when": {"deny": {"eq": "1"}}, "then": "NA"}, {"else": "MANUAL"}], manual=True,
         note="원격 데스크톱 비활성(fDenyTSConnections=1)이면 해당없음. Remote Desktop Users 구성원을 보고 판단"),
    rule("W-15", "사용자 개인키 사용 시 암호 입력", "상", ACC,
         [c("v", reg(r"HKLM:\SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection"))],
         [{"when": {"v": {"eq": "2"}}, "then": "GOOD"}, {"else": "VULN"}], note="기준: ForceKeyProtection=2(항상 암호 입력)"),
    rule("W-16", "공유 권한 및 사용자 그룹 설정", "상", SVC,
         [c("sh", "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Name -notmatch '\\$$'} | Select-Object -ExpandProperty Name"),
          c("acl", "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Name -notmatch '\\$$'} | Get-SmbShareAccess -ErrorAction SilentlyContinue | Select-Object Name,AccountName,AccessRight | Format-Table -AutoSize | Out-String -Width 200")],
         [{"when": {"sh_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"sh": {"absent": True}}, "then": "GOOD"},
          {"when": {"acl": {"regex": r"(?i)Everyone"}}, "then": "VULN"}, {"else": "GOOD"}],
         note="일반 공유 없음 또는 공유 권한에 Everyone 없음"),
    rule("W-17", "하드디스크 기본 공유 제거", "상", SVC,
         [c("reg", regs(LANMAN, ["AutoShareServer", "AutoShareWks"])),
          c("sh", "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^[A-Z]\\$$|^ADMIN\\$$'} | Select-Object -ExpandProperty Name")],
         [{"when": {"sh_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"sh": {"absent": True}, "reg": {"regex": r"AutoShare(Server|Wks)=0"}}, "then": "GOOD"},
          {"else": "VULN"}], note="기준: AutoShareServer(Wks)=0 이고 C$/ADMIN$ 등 기본 공유 없음"),
    rule("W-18", "불필요한 서비스 제거", "상", SVC,
         [c("svc", svc_running(["Alerter", "ClipSrv", "Messenger", "simptcp", "Browser", "CiSvc", "TrkWks", "TrkSvr",
                                "Fax", "Spooler", "WerSvc", "RemoteAccess", "TapiSrv", "TlntSvr", "WinHttpAutoProxySvc"]))],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}],
         note="가이드 목록의 불필요 서비스가 하나도 실행 중이 아니면 양호. 실행 중이면 업무 필요성 판단(Spooler 등)"),
    rule("W-19", "불필요한 IIS 서비스 구동 점검", "상", SVC, [c("svc", svc_running(["W3SVC", "IISADMIN"]))],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}], note="IIS 실행 중이면 필요성 판단"),
    rule("W-20", "NetBIOS 바인딩 서비스 구동 점검", "상", SVC,
         [c("nb", "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Select-Object -ExpandProperty TcpipNetbiosOptions")],
         [{"when": {"nb_ok": {"eq": "False"}}, "then": "MANUAL"}, {"when": {"nb": {"absent": True}}, "then": "MANUAL"},
          {"when": {"nb": {"regex": r"(?m)^[01]$"}}, "then": "VULN"}, {"else": "GOOD"}],
         note="TcpipNetbiosOptions 2=NetBIOS over TCP/IP 사용 안 함. 0(기본)/1 이면 바인딩됨"),
    rule("W-21", "암호화되지 않는 FTP 서비스 비활성화", "상", SVC, [c("svc", svc_running(["ftpsvc", "MSFTPSVC"]))],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}], note="FTP 실행 중이면 Secure FTP(TLS) 여부 확인"),
    rule("W-22", "FTP 디렉토리 접근권한 설정", "상", SVC, [c("svc", svc_running(["ftpsvc", "MSFTPSVC"]))],
         [{"when": {"svc": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}], manual=True, note="FTP 미사용이면 해당없음"),
    rule("W-23", "공유 서비스에 대한 익명 접근 제한 설정", "상", SVC,
         [c("svc", svc_running(["ftpsvc", "MSFTPSVC"])), c("v", reg(LSA, "RestrictAnonymous"))],
         [{"when": {"svc": {"absent": True}, "v": {"eq": "1"}}, "then": "GOOD"},
          {"when": {"svc": {"absent": True}}, "then": "MANUAL"}, {"else": "MANUAL"}],
         note="FTP 익명 인증은 IIS 설정 확인. 공유 익명 접근은 RestrictAnonymous=1"),
    rule("W-24", "FTP 접근 제어 설정", "상", SVC, [c("svc", svc_running(["ftpsvc", "MSFTPSVC"]))],
         [{"when": {"svc": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}], manual=True),
    rule("W-25", "DNS Zone Transfer 설정", "상", SVC,
         [c("svc", svc_running(["DNS"])),
          c("zones", "Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object {-not $_.IsAutoCreated} | Select-Object ZoneName,SecureSecondaries | Format-Table -AutoSize | Out-String -Width 200")],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"},
          {"when": {"zones": {"regex": r"TransferAnyServer"}}, "then": "VULN"},
          {"when": {"zones": {"regex": r"NoTransfer|TransferToSecureServers|TransferToZoneNameServer"}}, "then": "GOOD"},
          {"else": "MANUAL"}]),
    rule("W-26", "RDS(Remote Data Services)제거", "상", SVC,
         [c("major", "[Environment]::OSVersion.Version.Major"), c("iis", svc_running(["W3SVC"]))],
         [{"when": {"iis": {"absent": True}}, "then": "GOOD"}, {"when": {"major": {"ge": 6}}, "then": "GOOD"},
          {"else": "MANUAL"}], note="IIS 미사용 또는 Windows 2008 이상이면 양호"),
    rule("W-27", "최신 Windows OS Build 버전 적용", "상", PATCH,
         [c("os", "$o=Get-CimInstance Win32_OperatingSystem; $o.Caption+' '+$o.Version+' build '+$o.BuildNumber"),
          c("hf", "Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn | Select-Object -Last 5 HotFixID,InstalledOn | Format-Table -AutoSize | Out-String")],
         [{"else": "MANUAL"}], manual=True, note="빌드·핫픽스 목록을 벤더 최신과 대조"),
    rule("W-28", "터미널 서비스 암호화 수준 설정", "중", SVC,
         [c("deny", reg(RDP, "fDenyTSConnections")), c("lvl", reg(RDPTCP, "MinEncryptionLevel"))],
         [{"when": {"deny": {"eq": "1"}}, "then": "GOOD"}, {"when": {"lvl": {"ge": 2}}, "then": "GOOD"},
          {"when": {"lvl": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}],
         note="원격 데스크톱 미사용 또는 MinEncryptionLevel 2(클라이언트 호환) 이상"),
    rule("W-29", "불필요한 SNMP 서비스 구동 점검", "중", SVC, [c("svc", svc_running(["SNMP"]))],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}]),
    rule("W-30", "SNMP Community String 복잡성 설정", "중", SVC,
         [c("svc", svc_running(["SNMP"])),
          c("comm", f"(Get-Item -LiteralPath '{SNMP}\\ValidCommunities' -ErrorAction SilentlyContinue).Property")],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"},
          {"when": {"comm": {"regex": r"(?im)^(public|private)$"}}, "then": "VULN"},
          {"when": {"comm": {"exists": True}}, "then": "GOOD"}, {"else": "MANUAL"}]),
    rule("W-31", "SNMP Access Control 설정", "중", SVC,
         [c("svc", svc_running(["SNMP"])),
          c("mgr", f"(Get-Item -LiteralPath '{SNMP}\\PermittedManagers' -ErrorAction SilentlyContinue).Property")],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"when": {"mgr": {"exists": True}}, "then": "GOOD"},
          {"else": "VULN"}], note="PermittedManagers 에 허용 호스트가 있어야 양호"),
    rule("W-32", "DNS 서비스 구동 점검", "중", SVC,
         [c("svc", svc_running(["DNS"])),
          c("dyn", "Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object {-not $_.IsAutoCreated} | Select-Object ZoneName,DynamicUpdate | Format-Table -AutoSize | Out-String -Width 200")],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"when": {"dyn": {"regex": r"NonsecureAndSecure"}}, "then": "VULN"},
          {"when": {"dyn": {"regex": r"\bNone\b|\bSecure\b"}}, "then": "GOOD"}, {"else": "MANUAL"}]),
    rule("W-33", "HTTP/FTP/SMTP 배너 차단", "하", SVC,
         [c("svc", svc_running(["W3SVC", "ftpsvc", "MSFTPSVC", "SMTPSVC"]))],
         [{"when": {"svc": {"absent": True}}, "then": "NA"}, {"else": "MANUAL"}], manual=True, note="서비스가 있으면 배너 응답을 직접 확인"),
    rule("W-34", "Telnet 서비스 비활성화", "중", SVC,
         [c("svc", svc_running(["TlntSvr"])), c("auth", reg(r"HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0", "NTLM"))],
         [{"when": {"svc": {"absent": True}}, "then": "GOOD"}, {"when": {"auth": {"eq": "2"}}, "then": "GOOD"},
          {"else": "VULN"}], note="Telnet 미실행 또는 NTLM 전용 인증(NTLM=2)"),
    rule("W-35", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거", "중", SVC,
         [c("dsn", "Get-OdbcDsn -DsnType System -ErrorAction SilentlyContinue | Select-Object Name,DriverName | Format-Table -AutoSize | Out-String")],
         [{"when": {"dsn": {"absent": True}}, "then": "GOOD"}, {"else": "MANUAL"}], note="시스템 DSN 이 없으면 양호"),
    rule("W-36", "원격터미널 접속 타임아웃 설정", "중", SVC,
         [c("deny", reg(RDP, "fDenyTSConnections")), c("pol", reg(TSPOL, "MaxIdleTime")), c("tcp", reg(RDPTCP, "MaxIdleTime"))],
         [{"when": {"deny": {"eq": "1"}}, "then": "GOOD"},
          {"when": {"pol": {"gt": 0, "le": 1800000}}, "then": "GOOD"},
          {"when": {"tcp": {"gt": 0, "le": 1800000}}, "then": "GOOD"}, {"else": "VULN"}],
         note="기준: 유휴 세션 제한 30분(1800000ms) 이하. 원격 데스크톱 미사용이면 양호"),
    rule("W-37", "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검", "중", SVC,
         [c("tasks", "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*'} | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize | Out-String -Width 200")],
         [{"else": "MANUAL"}], manual=True, note="Microsoft 기본 작업 제외 목록. 명령·파일의 정당성은 분석자 판단"),
    rule("W-38", "주기적 보안 패치 및 벤더 권고사항 적용", "상", PATCH,
         [c("hf", "Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn | Select-Object -Last 10 HotFixID,InstalledOn | Format-Table -AutoSize | Out-String")],
         [{"else": "MANUAL"}], manual=True),
    rule("W-39", "백신 프로그램 업데이트", "상", PATCH,
         [c("age", "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge"),
          c("av", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName")],
         [{"when": {"age": {"le": 7}}, "then": "GOOD"}, {"when": {"age": {"exists": True}}, "then": "VULN"},
          {"else": "MANUAL"}], note="Defender 서명 7일 이내면 양호. 타사 백신은 콘솔에서 확인"),
    rule("W-40", "정책에 따른 시스템 로깅 설정", "중", LOG,
         [c("audit", "auditpol /get /category:* 2>&1 | Out-String -Width 200")],
         [{"when": {"audit_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"audit": {"regex": r"(?im)^\s*(Logon|로그온)\s{2,}(No Auditing|감사 안 함)"}}, "then": "VULN"},
          {"else": "MANUAL"}], note="로그온 감사가 '감사 안 함'이면 취약 확정, 나머지는 기관 감사 정책과 대조(관리자 권한 필요)"),
    rule("W-41", "NTP 및 시각 동기화 설정", "중", LOG,
         [c("ntp", "w32tm /query /status 2>&1 | Out-String")],
         [{"when": {"ntp": {"regex": r"(?i)Local CMOS Clock|로컬 CMOS 시계|Free-running"}}, "then": "VULN"},
          {"when": {"ntp": {"regex": r"(?i)(Source|원본)\s*:"}}, "then": "GOOD"}, {"else": "MANUAL"}]),
    rule("W-42", "이벤트 로그 관리 설정", "하", LOG,
         [c("small", "(Get-WinEvent -ListLog Application,Security,System -ErrorAction SilentlyContinue | Where-Object {$_.MaximumSizeInBytes -lt 10485760}).Count"),
          c("logs", "Get-WinEvent -ListLog Application,Security,System -ErrorAction SilentlyContinue | Select-Object LogName,MaximumSizeInBytes,LogMode | Format-Table -AutoSize | Out-String")],
         [{"when": {"small": {"eq": "0"}}, "then": "GOOD"}, {"when": {"small": {"ge": 1}}, "then": "VULN"},
          {"else": "MANUAL"}], evidence=["logs"], note="기준: 최대 로그 크기 10,240KB 이상. 덮어쓰기 90일 정책은 별도 확인"),
    rule("W-43", "이벤트 로그 파일 접근 통제 설정", "중", LOG,
         [c("acl", "icacls \"$env:SystemRoot\\System32\\winevt\\Logs\" 2>&1 | Out-String")],
         [{"when": {"acl_ok": {"eq": "False"}}, "then": "MANUAL"}, {"when": {"acl": {"regex": r"(?i)Everyone"}}, "then": "VULN"},
          {"else": "GOOD"}]),
    rule("W-44", "원격으로 액세스할 수 있는 레지스트리 경로", "상", SEC,
         [c("svc", "(Get-Service RemoteRegistry -ErrorAction SilentlyContinue).Status")],
         [{"when": {"svc": {"eq": "Running"}}, "then": "VULN"}, {"when": {"svc": {"exists": True}}, "then": "GOOD"},
          {"else": "GOOD"}], note="Remote Registry 중지·없음이면 양호"),
    rule("W-45", "백신 프로그램 설치", "상", SEC,
         [c("mp", "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled"),
          c("av", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName")],
         [{"when": {"mp": {"eq": "True"}}, "then": "GOOD"}, {"when": {"av": {"exists": True}}, "then": "GOOD"},
          {"when": {"mp": {"eq": "False"}}, "then": "VULN"}, {"else": "MANUAL"}]),
    rule("W-46", "SAM 파일 접근 통제 설정", "상", SEC,
         [c("acl", "icacls \"$env:SystemRoot\\System32\\config\\SAM\" 2>&1 | Out-String")],
         [{"when": {"acl_ok": {"eq": "False"}}, "then": "MANUAL"},
          {"when": {"acl": {"regex": r"(?im)^\s*(?!.*(Administrators|SYSTEM|관리자|성공|processed|파일을|Successfully))\S.*:\("}}, "then": "VULN"},
          {"when": {"acl": {"regex": r"(?i)Administrators|SYSTEM"}}, "then": "GOOD"}, {"else": "MANUAL"}],
         note="Administrators·SYSTEM 외 ACE 가 있으면 취약"),
    rule("W-47", "화면 보호기 설정", "하", SEC,
         [c("ss", regs(r"HKCU:\Control Panel\Desktop", ["ScreenSaveActive", "ScreenSaveTimeOut", "ScreenSaverIsSecure"]))],
         [{"when": {"act": {"eq": "1"}, "to": {"le": 600}, "sec": {"eq": "1"}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "ss", "regex": r"(?m)^ScreenSaveActive=(?P<act>.*)$"},
                  {"from": "ss", "regex": r"(?m)^ScreenSaveTimeOut=(?P<to>.*)$"},
                  {"from": "ss", "regex": r"(?m)^ScreenSaverIsSecure=(?P<sec>.*)$"}],
         note="접속 계정(HKCU) 기준. 기준: 사용, 10분(600초) 이하, 암호 보호"),
    rule("W-48", "로그온하지 않고 시스템 종료 허용", "상", SEC, [c("v", reg(POLSYS, "ShutdownWithoutLogon"))],
         [{"when": {"v": {"eq": "0"}}, "then": "GOOD"}, {"when": {"v": {"eq": "1"}}, "then": "VULN"}, {"else": "MANUAL"}],
         note="값 없음은 서버(0)/워크스테이션(1) 기본값이 달라 확인"),
    rule("W-49", "원격 시스템에서 강제로 시스템 종료", "상", SEC,
         [c("adm", "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object -ExpandProperty Name")],
         [{"else": "MANUAL"}], manual=True, note="SeRemoteShutdownPrivilege 는 secedit 전용 — 로컬 보안 정책에서 확인"),
    rule("W-50", "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료", "상", SEC, [c("v", reg(LSA, "CrashOnAuditFail"))],
         [{"when": {"v": {"regex": r"^[12]$"}}, "then": "VULN"}, {"else": "GOOD"}], note="값 없음 = 기본값 0(사용 안 함)"),
    rule("W-51", "SAM 계정과 공유의 익명 열거 허용 안 함", "상", SEC, [c("v", reg(LSA, "RestrictAnonymous"))],
         [{"when": {"v": {"eq": "1"}}, "then": "GOOD"}, {"when": {"v": {"eq": "0"}}, "then": "VULN"}, {"else": "MANUAL"}]),
    rule("W-52", "Autologon 기능 제어", "상", SEC, [c("v", reg(WINLOGON, "AutoAdminLogon"))],
         [{"when": {"v": {"eq": "1"}}, "then": "VULN"}, {"else": "GOOD"}]),
    rule("W-53", "이동식 미디어 포맷 및 꺼내기 허용", "상", SEC, [c("v", reg(WINLOGON, "AllocateDASD"))],
         [{"when": {"v": {"regex": r"^[12]$"}}, "then": "VULN"}, {"else": "GOOD"}], note="값 없음/0 = Administrators 만"),
    rule("W-54", "Dos 공격 방어 레지스트리 설정", "중", SEC,
         [c("t", regs(TCPIP, ["SynAttackProtect", "EnableDeadGWDetect", "EnableICMPRedirect", "KeepAliveTime"]))],
         [{"when": {"syn": {"ge": 1}, "gw": {"eq": "0"}, "icmp": {"eq": "0"}, "ka": {"le": 300000}}, "then": "GOOD"},
          {"else": "VULN"}],
         extract=[{"from": "t", "regex": r"(?m)^SynAttackProtect=(?P<syn>.*)$"},
                  {"from": "t", "regex": r"(?m)^EnableDeadGWDetect=(?P<gw>.*)$"},
                  {"from": "t", "regex": r"(?m)^EnableICMPRedirect=(?P<icmp>.*)$"},
                  {"from": "t", "regex": r"(?m)^KeepAliveTime=(?P<ka>.*)$"}],
         note="기준: SynAttackProtect≥1, EnableDeadGWDetect=0, EnableICMPRedirect=0, KeepAliveTime≤300000"),
    rule("W-55", "사용자가 프린터 드라이버를 설치할 수 없게 함", "중", SEC,
         [c("v", reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers", "AddPrinterDrivers"))],
         [{"when": {"v": {"eq": "1"}}, "then": "GOOD"}, {"else": "VULN"}]),
    rule("W-56", "SMB 세션 중단 관리 설정", "중", SEC,
         [c("t", regs(LANMAN, ["EnableForcedLogoff", "AutoDisconnect"]))],
         [{"when": {"fl": {"eq": "1"}, "ad": {"le": 15}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "t", "regex": r"(?m)^EnableForcedLogoff=(?P<fl>.*)$"},
                  {"from": "t", "regex": r"(?m)^AutoDisconnect=(?P<ad>.*)$"}],
         note="기준: 로그온 시간 만료 시 연결 끊기 사용, 유휴 15분 이하"),
    rule("W-57", "로그온 시 경고 메시지 설정", "하", SEC,
         [c("t", regs(POLSYS, ["LegalNoticeCaption", "LegalNoticeText"]))],
         [{"when": {"cap": {"regex": r"\S"}, "txt": {"regex": r"\S"}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "t", "regex": r"(?m)^LegalNoticeCaption=(?P<cap>.*)$"},
                  {"from": "t", "regex": r"(?m)^LegalNoticeText=(?P<txt>.*)$"}]),
    rule("W-58", "사용자별 홈 디렉터리 권한 설정", "중", SEC,
         [c("acl", "Get-ChildItem \"$env:SystemDrive\\Users\" -Directory -ErrorAction SilentlyContinue | Where-Object {$_.Name -notin @('Public','Default','Default User','All Users')} | ForEach-Object { icacls $_.FullName 2>&1 } | Out-String -Width 200")],
         [{"when": {"acl_ok": {"eq": "False"}}, "then": "MANUAL"}, {"when": {"acl": {"regex": r"(?i)Everyone"}}, "then": "VULN"},
          {"else": "GOOD"}]),
    rule("W-59", "LAN Manager 인증 수준", "중", SEC, [c("v", reg(LSA, "LmCompatibilityLevel"))],
         [{"when": {"v": {"ge": 3}}, "then": "GOOD"}, {"when": {"v": {"exists": True}}, "then": "VULN"}, {"else": "MANUAL"}],
         note="기준: 3 이상(NTLMv2 응답만 보냄). 값 없음은 OS 기본값(2008R2+ 는 3)이라 확인"),
    rule("W-60", "보안 채널 데이터 디지털 암호화 또는 서명", "중", SEC,
         [c("t", regs(NETLOGON, ["RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel"]))],
         [{"when": {"a": {"eq": "1"}, "b": {"eq": "1"}, "c": {"eq": "1"}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "t", "regex": r"(?m)^RequireSignOrSeal=(?P<a>.*)$"},
                  {"from": "t", "regex": r"(?m)^SealSecureChannel=(?P<b>.*)$"},
                  {"from": "t", "regex": r"(?m)^SignSecureChannel=(?P<c>.*)$"}]),
    rule("W-61", "파일 및 디렉토리 보호", "중", SEC,
         [c("fs", "Get-Volume -ErrorAction SilentlyContinue | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystemType -notin @('NTFS','ReFS')} | Select-Object -ExpandProperty DriveLetter"),
          c("all", "Get-Volume -ErrorAction SilentlyContinue | Where-Object {$_.DriveLetter} | Select-Object DriveLetter,FileSystemType,DriveType | Format-Table -AutoSize | Out-String")],
         [{"when": {"all_ok": {"eq": "False"}}, "then": "MANUAL"}, {"when": {"fs": {"absent": True}}, "then": "GOOD"},
          {"else": "VULN"}], evidence=["all"]),
    rule("W-62", "시작 프로그램 목록 분석", "중", SEC,
         [c("st", "Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name,Command,Location | Format-Table -AutoSize | Out-String -Width 200")],
         [{"else": "MANUAL"}], manual=True),
    rule("W-63", "도메인 컨트롤러-사용자의 시간 동기화", "중", SEC,
         [c("t", regs(r"HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config", ["MaxPosPhaseCorrection", "MaxNegPhaseCorrection"]))],
         [{"when": {"pos": {"le": 300}, "neg": {"le": 300}}, "then": "GOOD"}, {"else": "VULN"}],
         extract=[{"from": "t", "regex": r"(?m)^MaxPosPhaseCorrection=(?P<pos>.*)$"},
                  {"from": "t", "regex": r"(?m)^MaxNegPhaseCorrection=(?P<neg>.*)$"}],
         note="기준: 최대 허용 오차 5분(300초) 이하"),
    rule("W-64", "윈도우 방화벽 설정", "중", SEC,
         [c("fw", "Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled | Format-Table -AutoSize | Out-String")],
         [{"when": {"fw_ok": {"eq": "False"}}, "then": "MANUAL"}, {"when": {"fw": {"absent": True}}, "then": "MANUAL"},
          {"when": {"fw": {"regex": r"(?m)\bFalse\b"}}, "then": "VULN"}, {"else": "GOOD"}]),
]


def main(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in RULES:
        (out_dir / f"{r['id']}.yaml").write_text(
            f"# {r['id']} {r['name']} — Windows 선언형 룰(PowerShell 조회 전용). 생성: scripts/gen_rules_windows.py\n"
            + yaml.safe_dump(r, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8", newline="\n")
    print(f"{len(RULES)} rules -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rulepacks/kisa-2026/rules")))
