"""원격 명령 안전 정책 — 변경 명령은 잡고, 룰팩의 실제 읽기전용 명령은 통과해야 한다."""

from __future__ import annotations

import glob
from pathlib import Path

import pytest
import yaml

from infraguard.rules.policy import check, check_argv

ROOT = Path(__file__).resolve().parents[2]

BAD = [
    ("sh", "rm -rf /tmp/x"), ("sh", "cat /etc/passwd > /tmp/out"), ("sh", "grep x /etc/shadow | tee /tmp/a"),
    ("sh", "sed -i 's/a/b/' /etc/ssh/sshd_config"), ("sh", "systemctl restart sshd"), ("sh", "service sshd restart"),
    ("sh", "find / -name core -delete"), ("sh", "sudo rm x"), ("sh", "echo hi | sh"), ("sh", "curl http://x"),
    ("sh", "awk 'BEGIN{system(\"rm x\")}'"), ("sh", r"printf 'alter system set x=1;\n' | sqlplus -S / as sysdba"),
    ("sh", "ls; chmod 600 /etc/passwd"), ("sh", "x=$(rm y)"), ("sh", "ls `rm y`"), ("sh", "crontab -r"),
    ("sh", "iptables -F"), ("sh", "ls 2>/tmp/err"), ("sh", "xargs rm < list"), ("sh", "python3 -c 'import os'"),
    ("powershell", r"Set-ItemProperty HKLM:\x -Name a -Value 1"), ("powershell", "Get-Process | Stop-Process"),
    ("powershell", "net user igtest /add"), ("powershell", r"reg add HKLM\x /v a /d 1"),
    ("powershell", r"Get-Content x > C:\out.txt"), ("powershell", "iex 'ls'"), ("powershell", "(Get-Item x).Delete()"),
    ("powershell", r"icacls C:\x /grant Everyone:F"), ("powershell", "cmd /c dir"), ("powershell", "format d:"),
    ("powershell", "Invoke-WebRequest http://x"), ("powershell", "Get-Content x | Out-File y"),
    ("raw", "configure terminal"), ("raw", "write memory"), ("raw", "set system services telnet"), ("raw", "reload"),
]
OK = [
    ("sh", "ls -ld /etc/passwd 2>/dev/null | head -1"), ("sh", "systemctl is-active sshd 2>/dev/null"),
    ("sh", "service sshd status"), ("sh", "find /etc -perm -0002 2>/dev/null | head -20"),
    ("sh", "(command -v nft >/dev/null && nft list ruleset) || iptables -L -n"),
    ("sh", 'for p in /etc/crontab /etc/cron.d; do [ -e "$p" ] && echo "$p"; done'),
    ("sh", "rpm -qa --last 2>/dev/null | head -5"),
    ("sh", r'export PATH="$ORACLE_HOME/bin:$PATH"; printf "set heading off\nselect name from v\$parameter;\n" | sqlplus -S -L / as sysdba'),
    ("sh", "awk -F: '$3==0 {print $1}' /etc/passwd"), ("sh", "sudo -n true 2>&1"), ("sh", "crontab -l 2>/dev/null"),
    ("powershell", "Get-LocalUser | Select-Object Name | Format-Table -AutoSize | Out-String -Width 200"),
    ("powershell", r"Get-ItemProperty 'HKLM:\x' -ErrorAction SilentlyContinue | Select-Object a"),
    ("powershell", "net accounts"), ("powershell", r"reg query HKLM\x /v a 2>$null"),
    ("powershell", "auditpol /get /category:* 2>&1 | Out-String"), ("powershell", "w32tm /query /status 2>&1"),
    ("powershell", r"icacls C:\Windows\x 2>$null"), ("powershell", "Get-Volume | Format-Table"),
    ("raw", "show running-config | include aaa"), ("raw", "show configuration | display set"),
]


@pytest.mark.parametrize(("shell", "cmd"), BAD)
def test_write_commands_rejected(shell: str, cmd: str) -> None:
    assert check(shell, cmd), cmd


@pytest.mark.parametrize(("shell", "cmd"), OK)
def test_readonly_commands_pass(shell: str, cmd: str) -> None:
    assert check(shell, cmd) == [], cmd


def test_argv_forms() -> None:
    assert check_argv(["env", "ORACLE_HOME=/x", "sh", "-c", "rm x"])
    assert check_argv(["powershell", "-NoProfile", "-Command", "Get-Date"]) == []
    assert check_argv(["show version"]) == []
    assert check_argv(["unknown-binary", "x"])           # 형태를 모르면 통과시키지 않는다


def test_whole_rulepack_is_readonly() -> None:
    """동봉 룰팩 356개 수집 명령 전부 정책 통과. 룰 하나 고칠 때 여기서 걸리면 룰이 틀린 것이다."""
    n = 0
    for f in sorted(glob.glob(str(ROOT / "rulepacks/kisa-2026/rules/*.yaml"))):
        d = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
        for b in [d, *d.get("variants", [])]:
            sh = b.get("shell", d.get("shell", "sh"))
            for c in b.get("collect", []):
                n += 1
                assert check(sh, c["cmd"]) == [], (d["id"], c["cmd"])
    assert n > 300
