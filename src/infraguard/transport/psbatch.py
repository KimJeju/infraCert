"""PowerShell 수집 명령 배치 — 룰 N개의 명령을 스크립트 하나로 묶어 프로세스 1회로 받는다.

WinRM 은 run_ps 마다 powershell.exe 를 새로 띄워(~1s) 64룰이면 1분이 걸린다. 명령을 마커로 구분한 스크립트
하나로 보내고 명령별 stdout·성공여부를 되찾는다. 명령은 룰 파일의 상수 문자열이라 스크립트 조립이 인젝션 경계가
되지 않는다(룰팩 무결성 검증이 그 앞단).
"""

from __future__ import annotations

import re

BEGIN = "@@IG_BEGIN {i}@@"
END = "@@IG_END {i} rc={rc}@@"
_BLOCK_RE = re.compile(r"@@IG_BEGIN (\d+)@@\r?\n(.*?)\r?\n?@@IG_END \1 rc=(\d)@@", re.S)


def build_script(cmds: list[str]) -> str:
    """각 명령을 스크립트블록으로 감싸 실행. 종료 실패(예외)·비정상 종료($? false) 는 rc=1."""
    parts = ["$ProgressPreference='SilentlyContinue'"]
    for i, cmd in enumerate(cmds):
        parts.append(
            f"Write-Output '{BEGIN.format(i=i)}'\n"
            # $? 는 파이프 끝(Out-String) 성공만 본다 → 네이티브 명령(icacls 등) 실패는 $LASTEXITCODE 로 잡는다
            f"$global:LASTEXITCODE = 0\n"
            f"try {{ $__o = & {{ {cmd} }} 2>&1 | Out-String -Width 400; "
            f"$__rc = if ($? -and ($LASTEXITCODE -eq 0)) {{ 0 }} else {{ 1 }} }}\n"
            f"catch {{ $__o = $_.Exception.Message; $__rc = 1 }}\n"
            f"Write-Output $__o\n"
            f"Write-Output \"@@IG_END {i} rc=$__rc@@\""
        )
    return "\n".join(parts)


def parse_output(text: str, cmds: list[str]) -> dict[str, tuple[str, int]]:
    """명령 → (stdout, rc). 마커가 깨진 블록은 빠진다(호출자가 개별 실행으로 폴백)."""
    out: dict[str, tuple[str, int]] = {}
    for m in _BLOCK_RE.finditer(text):
        i, body, rc = int(m.group(1)), m.group(2), int(m.group(3))
        if 0 <= i < len(cmds):
            out[cmds[i]] = (body, rc)
    return out
