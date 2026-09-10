"""Unix/Linux 네이티브 룰 (KISA U-xx 일부, B안 증명용).

모든 명령은 상수 문자열이며 사용자 입력이 섞이지 않는다(인젝션 경로 없음).
읽기 전용 명령만 쓴다. 판단 불가·권한 부족은 MANUAL 로 근거만 남긴다 — 추측해 GOOD 주지 않는다.
AIX 는 /etc/security/* 기반(PAM 아님)이므로 분기한다.
"""

from __future__ import annotations

import re

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import NativeOutcome, register
from infraguard.transport.base import Connection

UNIX = ("linux", "aix", "solaris", "hpux", "freebsd", "darwin")


def _sh(conn: Connection, cmd: str, timeout: int = 60) -> tuple[str, bool]:
    """(stdout, ok). 실패해도 예외를 던지지 않는다."""
    r = conn.exec(["sh", "-c", cmd], timeout=timeout)
    return (r.stdout or ""), (r.ok and not r.error)


def _perm_owner(conn: Connection, path: str) -> tuple[str, str, str] | None:
    """ls -l 로 (권한문자열, 소유자, 원문). stat 없는 AIX 도 동작."""
    out, ok = _sh(conn, f"ls -ld {path} 2>/dev/null")
    if not ok or not out.strip():
        return None
    parts = out.split()
    if len(parts) < 3:
        return None
    return parts[0], parts[2], out.strip()


def _mode_bits(perm: str) -> int:
    """'-rw-r-----' → 0o640. 특수비트(s/t)는 실행비트로 취급."""
    bits = 0
    for i, ch in enumerate(perm[1:10]):
        if ch not in "-":
            bits |= 1 << (8 - i)
    return bits


def _file_perm_rule(paths: str | tuple[str, ...], max_mode: int, owner: str = "root",
                    group_allow: dict[str, int] | None = None) -> NativeOutcome:
    """파일 권한 룰 생성기. paths 가 여러 개면 존재하는 첫 파일을 본다(예: syslog/rsyslog).

    group_allow: {그룹명: 허용상한}. 예) /etc/shadow 는 Debian 계열에서 640 root:shadow 가 표준.
    """
    cands = (paths,) if isinstance(paths, str) else paths

    def _run(conn: Connection, _env: RemoteEnvironment) -> NativeOutcome:
        for path in cands:
            po = _perm_owner(conn, path)
            if po is not None:
                break
        else:
            return NativeOutcome("NA", f"{' / '.join(cands)} 없음 또는 읽기 불가")
        perm, own, raw = po
        parts = raw.split()
        grp = parts[3] if len(parts) > 3 else ""
        mode = _mode_bits(perm)
        limit = max_mode
        note = ""
        if group_allow and grp in group_allow:
            limit = max(limit, group_allow[grp])
            note = f" (그룹 {grp} 예외: {oct(group_allow[grp])} 허용)"
        ok = (own == owner) and (mode & ~limit) == 0
        return NativeOutcome(
            "GOOD" if ok else "VULN",
            f"{raw}\n기준: 소유자 {owner}, 권한 {oct(max_mode)} 이하{note} / 현재 {oct(mode)}",
        )
    return _run


# ---------------------------------------------------------------- 계정관리
@register("U-01", "root 계정 원격 접속 제한", "상", UNIX)
def u01(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    ev: list[str] = []
    if env.os == "aix":
        out, ok = _sh(conn, "lssec -f /etc/security/user -s root -a rlogin 2>/dev/null")
        ev.append(out.strip() or "(lssec 실패)")
        if ok and "rlogin=false" in out:
            return NativeOutcome("GOOD", "\n".join(ev))
        return NativeOutcome("VULN" if ok else "MANUAL", "\n".join(ev))
    out, ok = _sh(conn, "grep -iE '^\\s*PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
    ev.append(out.strip() or "PermitRootLogin 미설정(기본값)")
    if not ok and not out.strip():
        return NativeOutcome("MANUAL", "\n".join(ev) + "\nsshd_config 읽기 불가 — 확인 필요")
    vals = re.findall(r"PermitRootLogin\s+(\S+)", out, re.I)
    last = vals[-1].lower() if vals else "yes"   # OpenSSH 기본값은 prohibit-password 이나 보수적으로
    return NativeOutcome("GOOD" if last in ("no", "prohibit-password", "without-password") else "VULN",
                         "\n".join(ev))


@register("U-02", "비밀번호 복잡성·최소길이 설정", "상", UNIX)
def u02(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    if env.os == "aix":
        out, ok = _sh(conn, "lssec -f /etc/security/user -s default -a minlen -a minalpha -a minother 2>/dev/null")
        m = re.search(r"minlen=(\d+)", out)
        if not ok or not m:
            return NativeOutcome("MANUAL", out.strip() or "lssec 실패")
        return NativeOutcome("GOOD" if int(m.group(1)) >= 8 else "VULN", out.strip())
    out, _ = _sh(conn, "grep -E '^\\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null; "
                       "grep -hE 'pam_pwquality|pam_cracklib|minlen' /etc/pam.d/system-auth "
                       "/etc/pam.d/common-password /etc/security/pwquality.conf 2>/dev/null")
    m = re.search(r"minlen\s*=\s*(\d+)", out) or re.search(r"PASS_MIN_LEN\s+(\d+)", out)
    if not m:
        return NativeOutcome("MANUAL", out.strip() or "설정 없음 — 정책 확인 필요")
    return NativeOutcome("GOOD" if int(m.group(1)) >= 8 else "VULN", out.strip())


@register("U-03", "계정 잠금 임계값 설정", "상", UNIX)
def u03(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    if env.os == "aix":
        out, ok = _sh(conn, "lssec -f /etc/security/user -s default -a loginretries 2>/dev/null")
        m = re.search(r"loginretries=(\d+)", out)
        if not ok or not m:
            return NativeOutcome("MANUAL", out.strip() or "lssec 실패")
        n = int(m.group(1))
        return NativeOutcome("GOOD" if 0 < n <= 10 else "VULN", out.strip())
    out, _ = _sh(conn, "grep -hE 'pam_faillock|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/common-auth "
                       "/etc/pam.d/password-auth 2>/dev/null; grep -E '^\\s*deny' /etc/security/faillock.conf 2>/dev/null")
    m = re.search(r"deny\s*=\s*(\d+)", out)
    if not m:
        return NativeOutcome("VULN" if not out.strip() else "MANUAL",
                             out.strip() or "잠금 모듈(pam_faillock/tally2) 미설정")
    n = int(m.group(1))
    return NativeOutcome("GOOD" if 0 < n <= 10 else "VULN", out.strip())


@register("U-04", "비밀번호 파일 보호(shadow 사용)", "상", UNIX)
def u04(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    if env.os == "aix":
        po = _perm_owner(conn, "/etc/security/passwd")
        if po is None:
            return NativeOutcome("MANUAL", "/etc/security/passwd 접근 불가")
        perm, own, raw = po
        return NativeOutcome("GOOD" if own == "root" and (_mode_bits(perm) & 0o077) == 0 else "VULN", raw)
    out, _ = _sh(conn, "awk -F: '$2 != \"x\" && $2 != \"*\" && $2 != \"!\" {print $1\":\"$2}' /etc/passwd 2>/dev/null | head -20")
    if out.strip():
        return NativeOutcome("VULN", "passwd 2번째 필드에 해시/평문 존재:\n" + out.strip())
    po = _perm_owner(conn, "/etc/shadow")
    return NativeOutcome("GOOD" if po else "MANUAL", (po[2] if po else "/etc/shadow 확인 불가"))


@register("U-05", "root 이외의 UID 0 금지", "상", UNIX)
def u05(conn: Connection, _env: RemoteEnvironment) -> NativeOutcome:
    out, ok = _sh(conn, "awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null")
    if not ok:
        return NativeOutcome("MANUAL", "/etc/passwd 읽기 실패")
    users = [u for u in out.split() if u]
    extra = [u for u in users if u != "root"]
    return NativeOutcome("VULN" if extra else "GOOD", "UID 0 계정: " + ", ".join(users))


@register("U-06", "root 계정 su 제한", "하", UNIX)
def u06(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    if env.os == "aix":
        out, ok = _sh(conn, "lssec -f /etc/security/user -s root -a sugroups 2>/dev/null")
        if not ok or not out.strip():
            return NativeOutcome("MANUAL", "lssec 실패")
        return NativeOutcome("VULN" if "sugroups=ALL" in out else "GOOD", out.strip())
    out, _ = _sh(conn, "grep -E '^\\s*auth.*pam_wheel' /etc/pam.d/su 2>/dev/null; ls -l "
                       "$(command -v su) 2>/dev/null")
    return NativeOutcome("GOOD" if "pam_wheel" in out else "VULN", out.strip() or "pam_wheel 미설정")


# ------------------------------------------------------------ 파일·디렉터리
register("U-09", "/etc/passwd 파일 소유자 및 권한", "상", UNIX)(_file_perm_rule("/etc/passwd", 0o644))
register("U-10", "/etc/shadow 파일 소유자 및 권한", "상", ("linux", "solaris", "hpux"))(
    _file_perm_rule("/etc/shadow", 0o400, group_allow={"shadow": 0o640}))
register("U-11", "/etc/hosts 파일 소유자 및 권한", "상", UNIX)(_file_perm_rule("/etc/hosts", 0o600))
register("U-12", "/etc/(x)inetd.conf 소유자 및 권한", "상", UNIX)(
    _file_perm_rule(("/etc/inetd.conf", "/etc/xinetd.conf"), 0o600))
register("U-13", "/etc/(r)syslog.conf 소유자 및 권한", "상", UNIX)(
    _file_perm_rule(("/etc/syslog.conf", "/etc/rsyslog.conf", "/etc/syslog-ng/syslog-ng.conf"), 0o644))


@register("U-15", "world writable 파일 점검", "상", UNIX)
def u15(conn: Connection, _env: RemoteEnvironment) -> NativeOutcome:
    # 전체 순회는 오래 걸린다. -xdev 로 로컬 FS 한정, 표본 50개.
    out, ok = _sh(conn, "find / -xdev -type f -perm -0002 2>/dev/null | head -50", timeout=600)
    if not ok and not out.strip():
        return NativeOutcome("MANUAL", "find 실행 실패/권한 부족")
    files = [f for f in out.splitlines() if f.strip()]
    if not files:
        return NativeOutcome("GOOD", "world-writable 일반파일 없음(-xdev)")
    return NativeOutcome("VULN", f"{len(files)}개(표본):\n" + "\n".join(files))


@register("U-45", "UMASK 설정 관리", "중", UNIX)
def u45(conn: Connection, _env: RemoteEnvironment) -> NativeOutcome:
    # 시스템 기본 정책(설정파일)만 본다. 점검 계정 세션의 umask(USERGROUPS_ENAB 등)는 판정에 섞지 않는다.
    out, _ = _sh(conn, "grep -HiE '^\\s*umask' /etc/profile /etc/bashrc /etc/bash.bashrc "
                       "/etc/login.defs /etc/csh.cshrc /etc/profile.d/*.sh /etc/security/user 2>/dev/null")
    vals = re.findall(r"(?i)umask\s*=?\s*(\d{3,4})", out)
    ev = out.strip() or "설정파일에 umask 지정 없음"
    if not vals:
        return NativeOutcome("MANUAL", ev + "\n※ 기본 umask 정책을 운영자에게 확인")
    ok = all((int(v, 8) & 0o022) == 0o022 for v in vals)
    return NativeOutcome("GOOD" if ok else "VULN", ev)


@register("U-64", "주기적 보안패치 및 벤더 권고사항 적용", "상", UNIX)
def u64(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    cmd = "oslevel -s 2>/dev/null; instfix -i 2>/dev/null | tail -3" if env.os == "aix" else \
          "uname -srm; cat /etc/os-release 2>/dev/null | head -3; " \
          "(rpm -qa --last 2>/dev/null | head -5) || (ls -lt /var/lib/dpkg/info/*.list 2>/dev/null | head -5)"
    out, _ = _sh(conn, cmd, timeout=120)
    return NativeOutcome("MANUAL", (out.strip() or "버전 정보 수집 실패") + "\n※ 최신 패치 적용 여부는 벤더 공지 대조 필요")
