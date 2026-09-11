r"""WinRM 실접속 자가점검 — 이 PC(또는 지정 호스트)에 WinRM 으로 붙어 windows-native 64룰을 돌려 본다.

    .\.venv\Scripts\python.exe scripts\winrm_selfcheck.py [--host localhost] [--port 5985] [--user 계정] [--ssl]

비밀번호는 getpass 로만 받고 어디에도 기록하지 않는다(Secret 래퍼 → transport 계층에서만 reveal).
출력: 연결/probe 결과, 룰별 판정·근거 첫 줄, 판정 분포. 실패 원인은 그대로 보여 준다(추측 안 함).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from infraguard.credentials.secret import Secret  # noqa: E402
from infraguard.credentials.session import Credential  # noqa: E402
from infraguard.orchestrator.native_runner import run_native  # noqa: E402
from infraguard.rulepack import loader  # noqa: E402
from infraguard.transport.winrm import WinRMConnection, WinRMTarget  # noqa: E402


def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(errors="replace")   # 콘솔 코드페이지가 못 그리는 글자로 죽지 않게
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=5985)
    ap.add_argument("--user", default=os.environ.get("USERNAME", ""))
    ap.add_argument("--ssl", action="store_true")
    ap.add_argument("--profile", default="windows-native")
    ap.add_argument("--full", action="store_true", help="근거 전문 출력")
    a = ap.parse_args(argv)

    pw = getpass.getpass(f"{a.user}@{a.host} 비밀번호(표시 안 됨): ")
    cred = Credential(cred_id="selfcheck", username=a.user, kind="password", password=Secret(pw))
    del pw
    conn = WinRMConnection(WinRMTarget(a.host, a.port, cred, use_ssl=a.ssl))
    t0 = time.monotonic()
    try:
        conn.connect()
    except Exception as e:  # noqa: BLE001 - 원인을 그대로 보여 준다
        print(f"연결 실패 ({type(e).__name__}): {e}")
        return 1
    env = conn.probe()
    print(f"연결 OK {time.monotonic() - t0:.1f}s  os={env.os} {env.os_version}  host={env.hostname}  user={env.user}"
          + (f"  notes={env.notes}" if env.notes else ""))

    pack = loader.load(ROOT / "rulepacks" / "kisa-2026")
    rules = pack.profiles[a.profile].native
    t1 = time.monotonic()
    findings, errors = run_native(conn, env, rules, progress=lambda rid, i, n: print(f"\r{rid} ({i}/{n})", end=""))
    print(f"\r{len(rules)}룰 {time.monotonic() - t1:.1f}s")
    conn.close()

    c: Counter[str] = Counter()
    for f in findings:
        c[f.verdict_raw] += 1
        ev = f.evidence_raw if a.full else " | ".join(ln.strip() for ln in f.evidence_raw.splitlines() if ln.strip())[:100]
        print(f"{f.rule_id} {f.verdict_raw:6s} {ev}")
    for e in errors:
        c["ERROR"] += 1
        print(f"{e.rule_id} ERROR  {e.reason}")
    print(dict(c))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
