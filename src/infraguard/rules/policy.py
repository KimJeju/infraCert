"""원격 명령 안전 정책 — 읽기전용이 아닌 명령을 정적으로 거른다.

룰팩은 데이터 디렉터리다. YAML 에 셸 명령이 들어가는 순간부터 "이 명령이 대상을 바꾸지 않는가"는
룰 작성자의 양심이 아니라 제품이 보장해야 한다. 두 곳에서 같은 함수를 부른다:
  1. 룰팩 로드(loader): 위반 룰이 하나라도 있으면 룰팩 실행을 막고 목록을 보여준다.
  2. 실행 직전(native_runner 의 연결 프록시): 로더를 우회한 경로(파이썬 룰·프리페치)도 같은 정책을 탄다.

정적 분석의 한계: 완전한 셸 파서가 아니다. 토큰 단위 거부 목록 + 리다이렉트 검사 + SQL 문두 검사.
ponytail: 우회 가능성이 남는 자리(awk 프로그램 안의 system(), 이중 인용 안의 $(…))는 문자열 검색으로만 막는다.
    필요해지면 shell 파서(bashlex)로 올린다.
"""

from __future__ import annotations

import re
import shlex

SH_DENY = frozenset("""
rm rmdir mv cp ln mkdir touch chmod chown chgrp chattr dd mkfs mkfs.ext4 mkfs.xfs mount umount tee truncate
reboot shutdown halt poweroff init telinit kill killall pkill
passwd chpasswd useradd userdel usermod groupadd groupdel groupmod chsh chfn
apt apt-get yum dnf pip pip3 installp smitty chdev chuser chsec rmuser mkuser mkgroup chfs crfs rmfs
swapon swapoff setenforce vi vim nano ed ex emacs
eval exec source . sh bash ksh csh zsh dash python python3 perl ruby
nc ncat curl wget ssh scp sftp telnet ftp tftp rsync
""".split())
# 하위 명령까지 봐야 하는 것: (명령, 허용 하위명령 정규식)
SH_SUBCMD_ALLOW: dict[str, re.Pattern[str]] = {
    "systemctl": re.compile(r"^(status|is-active|is-enabled|is-failed|show|cat|get-default|list-[a-z-]+)$"),
    "service": re.compile(r"^status$"),          # service X status 는 2번째 인자라 별도 처리
    "crontab": re.compile(r"^-l$"),
    "iptables": re.compile(r"^(-L|-S|-n|-v|--list|--list-rules|-t)"),
    "ip6tables": re.compile(r"^(-L|-S|-n|-v|--list|--list-rules|-t)"),
    "nft": re.compile(r"^list$"),
    "ufw": re.compile(r"^status$"),
    "firewall-cmd": re.compile(r"^--(list|get|state|query)"),
    "sysctl": re.compile(r"^(-a|-n|[a-z0-9_.]+)$"),
    "sed": re.compile(r"^(?!-i)"),               # -i 만 거부
    "find": re.compile(r"^(?!-(delete|exec|execdir|ok|okdir|fprint|fls)$)"),
    "sudo": re.compile(r"^-[nl]"),               # sudo -n/-l 만(정보). 그 외 sudo X 는 X 를 검사
    "rpm": re.compile(r"^-[qV]"),
    "xargs": re.compile(r"^(?!.)"),              # xargs 다음 단어를 명령으로 검사
    "nohup": re.compile(r"^(?!.)"),
    "timeout": re.compile(r"^(?!.)"),
    "command": re.compile(r"^-v$"),
    "su": re.compile(r"^(?!.)"),
}
SH_WRAPPERS = {"sudo", "xargs", "nohup", "timeout", "env", "command", "su", "time", "nice"}
SH_KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "in", "case",
               "esac", "!", "{", "}", "function", "select"}
SH_OPERATORS = {"|", "||", "&&", ";", "&", "(", ")", "`", ";;"}
SH_REDIRECT_OK = re.compile(r"^(/dev/null|&\d|&-)$")
SQL_ALLOW = frozenset("""
select with show set col column define whenever exit quit desc describe prompt var variable
""".split())
SQL_STMT_DENY_FIRST = frozenset("""
alter create drop insert update delete merge grant revoke truncate exec execute begin declare
shutdown startup purge audit noaudit call comment rename flashback spool host ! @ @@ commit rollback
""".split())

PS_VERB_DENY = re.compile(
    r"\b(Set|Remove|New|Stop|Start|Restart|Disable|Enable|Clear|Rename|Move|Copy|Add|Install|Uninstall|"
    r"Invoke|Register|Unregister|Update|Write|Out|Export|Import|Reset|Revoke|Grant|Block|Unblock|Suspend|"
    r"Resume|Repair|Initialize|Format|Mount|Dismount|Publish|Send|Push|Pop|Undo|Redo|Lock|Unlock|Limit|"
    r"Optimize|Merge|Split|Switch|Use|Wait|Debug|Trace|Enter|Exit|Join|Convert|Edit|Save|Restore|Backup|"
    r"Checkpoint|Complete|Confirm|Deny|Approve|Assert|Build|Deploy|Compress|Expand|Hide|Show|Skip|Step|"
    r"Submit|Sync|Ping|Connect|Disconnect|Read|Receive|Request|Resize|Search|Select|Test|Trace|Watch)-"
    r"([A-Za-z]+)\b")
PS_CMDLET_ALLOW = frozenset("""
out-string out-null format-table format-list format-wide format-custom write-output write-host
select-object select-string sort-object test-path test-netconnection convertto-json convertfrom-json
convertto-csv convertfrom-csv convertfrom-stringdata convertto-securestring convert-path
import-module start-sleep new-object new-timespan set-strictmode
compare-object measure-object group-object where-object foreach-object tee-object
""".split())
PS_TOKEN_DENY = [
    (re.compile(r"(?i)\biex\b|Invoke-Expression|\[ScriptBlock\]::Create|Add-Type|Invoke-Command|"
                r"Invoke-WebRequest|Invoke-RestMethod|Start-Process|Start-Job"), "실행/네트워크 cmdlet"),
    (re.compile(r"(?i)\.(Delete|Kill|SetValue|CreateSubKey|DeleteValue|DeleteSubKey|Stop|Start|Put|Create|"
                r"Invoke|Remove|Move|Rename|Terminate|Set)\s*\("), "변경 메서드 호출"),
    (re.compile(r"(?i)\bnet(\.exe)?\s+(user|localgroup|group|share|accounts)\b.*\s/(add|delete|del|active|"
                r"expires|passwordchg|passwordreq|times|comment|domain|maxpwage|minpwlen|uniquepw|lockout)\b"),
     "net 변경"),
    (re.compile(r"(?i)\breg(\.exe)?\s+(add|delete|import|restore|load|unload|copy|save)\b"), "reg 변경"),
    (re.compile(r"(?i)\bsc(\.exe)?\s+(config|stop|start|delete|create|pause|continue|failure|sdset)\b"), "sc 변경"),
    (re.compile(r"(?i)\bsecedit(\.exe)?\s+/(configure|import|validate|generaterollback)\b"), "secedit 변경"),
    (re.compile(r"(?i)\bauditpol(\.exe)?\s+/(set|clear|backup|restore|remove)\b"), "auditpol 변경"),
    (re.compile(r"(?i)\bicacls(\.exe)?\b.*\s/(grant|deny|remove|reset|setowner|inheritance|restore)\b"), "icacls 변경"),
    (re.compile(r"(?i)\bnetsh(\.exe)?\b.*\b(set|add|delete|reset|import)\b"), "netsh 변경"),
    (re.compile(r"(?i)\bwmic(\.exe)?\b.*\b(call|set|create|delete)\b"), "wmic 변경"),
    (re.compile(r"(?i)\bw32tm(\.exe)?\s+/(config|resync|register|unregister)\b"), "w32tm 변경"),
    (re.compile(r"(?i)\b(cmd|powershell|pwsh)(\.exe)?\s+(/c|/k|-c|-command|-enc|-e)\b"), "중첩 셸"),
    (re.compile(r"(?i)\b(shutdown|bcdedit|diskpart|cipher|takeown)(\.exe)?\b|\bformat(\.com)?\s+\w:|"
                r"\bschtasks(\.exe)?\s+/(create|delete|change|run)\b"), "시스템 변경 도구"),
]
RAW_ALLOW = re.compile(r"^\s*show\b", re.I)


class PolicyError(Exception):
    """정책 위반 명령. native_runner 가 ERROR 결과로 바꾼다."""


def check(shell: str, cmd: str) -> list[str]:
    """위반 사유 목록. 비어 있으면 통과."""
    if shell == "sh":
        return _check_sh(cmd)
    if shell == "powershell":
        return _check_ps(cmd)
    if shell == "raw":
        return [] if RAW_ALLOW.match(cmd) else [f"장비 명령은 show 로 시작해야 함: {cmd[:60]!r}"]
    return [f"알 수 없는 셸 {shell!r}"]


def check_argv(argv: list[str]) -> list[str]:
    """실행 직전 argv 형태(build_argv/파이썬 룰 공통)를 셸·명령으로 되돌려 검사."""
    a = list(argv)
    while len(a) >= 2 and a[0] == "env" and "=" in a[1]:      # env K=V … 접두(호스트 파라미터)
        a = [a[0]] + a[2:]
    if a and a[0] == "env":
        a = a[1:]
    if len(a) == 3 and a[0] in ("sh", "bash", "ksh") and a[1] == "-c":
        return _check_sh(a[2])
    if a and a[0] == "powershell" and "-Command" in a:
        return _check_ps(a[a.index("-Command") + 1])
    if len(a) == 1:
        return check("raw", a[0])
    return [f"검사 불가 argv 형태: {a[:3]!r}"]


# ------------------------------------------------------------------ sh
def _sh_tokens(cmd: str) -> list[str]:
    # 백틱 치환은 인용 안 문자열도 바꾸지만 여기선 실행이 아니라 분석이다 — `X` 의 X 를 명령으로 보게 한다
    lex = shlex.shlex(cmd.replace("`", " ; "), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError as e:      # 닫히지 않은 인용 — 파서가 못 읽는 명령은 실행도 안 시킨다
        raise PolicyError(f"명령 토큰화 실패: {e}") from e


def _check_sh(cmd: str) -> list[str]:
    bad: list[str] = []
    try:
        toks = _sh_tokens(cmd)
    except PolicyError as e:
        return [str(e)]
    expect_cmd = True
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith(">") or t in (">>", ">&", ">|") or re.fullmatch(r"\d?>>?", t) or t.endswith(">"):
            target = toks[i + 1] if i + 1 < len(toks) else ""
            if t.endswith("&"):            # 2>&1 → 토큰 '>&' + '1'
                target = "&" + target
            if not SH_REDIRECT_OK.match(target):
                bad.append(f"파일 리다이렉트: {t} {target!r}")
            i += 2
            continue
        if t in SH_OPERATORS or t in SH_KEYWORDS:
            expect_cmd = t != "in"            # for X in a b c — 목록은 명령이 아니다
            i += 1
            continue
        if t.startswith("<"):
            i += 2
            continue
        if expect_cmd:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t):   # VAR=x cmd
                i += 1
                continue
            word = t.rsplit("/", 1)[-1]
            nxt = toks[i + 1] if i + 1 < len(toks) else ""
            if word in SH_DENY:
                bad.append(f"거부 명령: {word}")
            elif word in SH_SUBCMD_ALLOW:
                pat = SH_SUBCMD_ALLOW[word]
                if word == "service":
                    if not (i + 2 < len(toks) and toks[i + 2] == "status"):
                        bad.append(f"service 는 status 만 허용: {' '.join(toks[i:i+3])!r}")
                elif word in SH_WRAPPERS and not pat.match(nxt):
                    expect_cmd = True          # sudo X / xargs X → X 를 명령으로 검사
                    i += 1
                    continue
                elif word == "find":
                    j = i + 1
                    while j < len(toks) and toks[j] not in SH_OPERATORS:
                        if not pat.match(toks[j]):
                            bad.append(f"find 액션 불허: {toks[j]!r}")
                        j += 1
                elif not pat.match(nxt):
                    bad.append(f"{word} 하위명령 불허: {nxt!r}")
            elif word == "awk":
                prog = " ".join(toks[i + 1:i + 4])
                if re.search(r"system\s*\(|print[f]?\s*[^;]*>\s*\"", prog):
                    bad.append("awk 프로그램에 system()/파일 출력")
            elif word == "sqlplus":
                pass
            expect_cmd = False
        i += 1
    if "sqlplus" in cmd:
        bad += _check_sql(cmd)
    return bad


def _check_sql(cmd: str) -> list[str]:
    """printf '…' | sqlplus 형태의 SQL 문두 검사. 문은 ; 또는 줄바꿈으로 나뉜다."""
    bad: list[str] = []
    text = ""
    for t in _sh_tokens(cmd):
        if "select" in t.lower() or "\\n" in t:
            text += t.replace("\\n", "\n") + "\n"
    for stmt in re.split(r"[;\n]", text):
        s = stmt.strip()
        if not s or s.startswith("--"):
            continue
        first = s.split()[0].lower().rstrip(";")
        if first in SQL_STMT_DENY_FIRST:
            bad.append(f"SQL 변경문: {s[:50]!r}")
    return bad


# ------------------------------------------------------------------ powershell
def _check_ps(cmd: str) -> list[str]:
    bad: list[str] = []
    for m in PS_VERB_DENY.finditer(cmd):
        name = m.group(0).lower()
        if name not in PS_CMDLET_ALLOW:
            bad.append(f"거부 cmdlet: {m.group(0)}")
    for pat, why in PS_TOKEN_DENY:
        if pat.search(cmd):
            bad.append(why)
    # 리다이렉트: > $null / 2>&1 / 2>$null 만
    stripped = re.sub(r"\d?>\s*\$null|2>&1|>&1", "", cmd)
    if re.search(r"(?<![-<])>>?\s*[^\s|)]", stripped):
        bad.append("파일 리다이렉트(>)")
    return sorted(set(bad))
