"""연결 사전검증 — 진단 시작 직후(probe 뒤) 몇 개의 읽기전용 명령으로 ERROR/MANUAL 이 뻔한 상황을 미리 드러낸다.

진단을 막지 않는다(사용자가 끌 수 있다). 발견 사항은 HostResult.preflight 로 남겨 진행 표와 결과에 보인다.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import load_all
from infraguard.transport.base import Connection

UNIX = ("linux", "aix", "solaris", "hpux", "freebsd", "darwin")
MIN_TMP_KB = 50 * 1024


def _sh(conn: Connection, cmd: str) -> str | None:
    try:
        r = conn.exec(["sh", "-c", cmd], timeout=15)
    except Exception:  # noqa: BLE001 - 사전검증이 진단을 죽이면 안 된다
        return None
    return (r.stdout or "").strip() if r.ok else None


def run(conn: Connection, env: RemoteEnvironment, *, native: Iterable[str], has_bundles: bool,
        missing_params: Iterable[str] = ()) -> list[str]:
    notes: list[str] = []
    if env.incomplete:
        notes.append("환경 식별 불완전(probe 실패) — 플랫폼 불일치 SKIPPED 가 많을 수 있음")
    for name in missing_params:
        notes.append(f"파라미터 {name} 미지정 — 해당 제품 점검은 수동확인으로 남음")
    if env.os not in UNIX:
        return notes

    reg = load_all()
    cmds = [c for rid in native if (r := reg.get(rid)) for _, c in r.collects]
    if env.privileged is False:
        sudo = _sh(conn, "sudo -n true 2>&1 && echo OK")
        notes.append("일반 계정" + ("(sudo -n 가능)" if sudo and sudo.endswith("OK") else
                                  " — root 전용 파일(shadow·sudoers 등)은 수동확인으로 남음"))
    if any("sqlplus" in c for c in cmds):
        oh = env.params.get("ORACLE_HOME", "")
        found = _sh(conn, f'test -x "{oh}/bin/sqlplus" && echo OK || command -v sqlplus') if oh else _sh(conn, "command -v sqlplus")
        if not found:
            notes.append("sqlplus 없음 — Oracle 룰 전부 실행 실패(ORACLE_HOME 파라미터 확인)")
    if has_bundles:
        df = _sh(conn, "df -kP /tmp 2>/dev/null | awk 'NR==2{print $4}'")
        if df and df.isdigit() and int(df) < MIN_TMP_KB:
            notes.append(f"/tmp 여유 {int(df) // 1024}MB — 번들 산출물 공간 부족 가능")
    ts = _sh(conn, "date +%s")
    if ts and ts.isdigit():
        skew = abs(int(ts) - int(time.time()))
        if skew > 300:
            notes.append(f"시간 편차 {skew}s — 로그 기준 판정(최근 패치·계정 만료 등) 해석 주의")
    return notes
