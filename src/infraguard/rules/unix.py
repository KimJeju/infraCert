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


@register("U-06", "사용자 계정 su 기능 제한", "상", UNIX)
def u06(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    if env.os == "aix":
        out, ok = _sh(conn, "lssec -f /etc/security/user -s root -a sugroups 2>/dev/null")
        if not ok or not out.strip():
            return NativeOutcome("MANUAL", "lssec 실패")
        return NativeOutcome("VULN" if "sugroups=ALL" in out else "GOOD", out.strip())
    out, _ = _sh(conn, "grep -E '^\\s*auth.*pam_wheel' /etc/pam.d/su 2>/dev/null; ls -l "
                       "$(command -v su) 2>/dev/null")
    return NativeOutcome("GOOD" if "pam_wheel" in out else "VULN", out.strip() or "pam_wheel 미설정")


@register("U-30", "UMASK 설정 관리", "중", UNIX)
def u30(conn: Connection, _env: RemoteEnvironment) -> NativeOutcome:
    # 시스템 기본 정책(설정파일)만 본다. 점검 계정 세션의 umask(USERGROUPS_ENAB 등)는 판정에 섞지 않는다.
    out, _ = _sh(conn, "grep -HiE '^\\s*umask' /etc/profile /etc/bashrc /etc/bash.bashrc "
                       "/etc/login.defs /etc/csh.cshrc /etc/profile.d/*.sh /etc/security/user 2>/dev/null")
    vals = re.findall(r"(?i)umask\s*=?\s*(\d{3,4})", out)
    ev = out.strip() or "설정파일에 umask 지정 없음"
    if not vals:
        return NativeOutcome("MANUAL", ev + "\n※ 기본 umask 정책을 운영자에게 확인")
    ok = all((int(v, 8) & 0o022) == 0o022 for v in vals)
    return NativeOutcome("GOOD" if ok else "VULN", ev)
