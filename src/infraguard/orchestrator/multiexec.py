"""Multi-Exec — 여러 호스트에 같은 **읽기전용** 명령을 동시에 실행한다(MobaXterm Multi-Exec 의 안전판).

안전장치:
  - 명령은 실행 전에 `rules/policy.check` 를 통과해야 한다(rm/mv/chmod/systemctl restart/리다이렉트… 거부).
  - 실행 직전 요약(읽기 전용 · 대상 N대 · 예상 변경 없음)을 사용자가 확인한다(UI).
  - 출력은 마스킹해서 workspace/logs/multiexec/ 에 감사 기록(완전삭제 대상).
  - 명령 라이브러리에 쓰기 명령은 등록 자체가 안 된다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from infraguard.assets.models import Host
from infraguard.core.models import Platform
from infraguard.result.masking import mask
from infraguard.rules.declarative import SHELLS
from infraguard.rules.policy import check

LIBRARY_FILE = Path(__file__).resolve().parents[1] / "data" / "command_library.yaml"


def shell_for(host: Host) -> str:
    if host.platform in (Platform.WINDOWS, Platform.PC):
        return "powershell"
    if host.platform == Platform.NETWORK:
        return "raw"
    return "sh"


def argv_for(shell: str, cmd: str) -> list[str]:
    return SHELLS[shell](cmd)


@dataclass(slots=True)
class ExecOutcome:
    host_id: str
    label: str
    shell: str
    cmd: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return not self.error and self.exit_code == 0

    def first_line(self) -> str:
        for ln in (self.stdout or self.stderr or self.error).splitlines():
            if ln.strip():
                return ln.strip()
        return ""


@dataclass(slots=True)
class Plan:
    """실행 전 확인용 요약."""
    cmd_by_shell: dict[str, str]
    hosts: list[Host]
    violations: dict[str, list[str]] = field(default_factory=dict)   # shell → 사유

    @property
    def read_only(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        lines = [f"대상 {len(self.hosts)}대", "예상 변경: 없음(읽기 전용 정책 통과)" if self.read_only else "⚠ 정책 위반 — 실행 불가"]
        for sh, cmd in self.cmd_by_shell.items():
            n = sum(1 for h in self.hosts if shell_for(h) == sh)
            lines.append(f"  [{sh}] {n}대: {cmd}")
            for why in self.violations.get(sh, []):
                lines.append(f"     ✕ {why}")
        return "\n".join(lines)


def plan(hosts: list[Host], cmd_by_shell: dict[str, str]) -> Plan:
    p = Plan(cmd_by_shell=dict(cmd_by_shell), hosts=list(hosts))
    for sh in {shell_for(h) for h in hosts}:
        cmd = cmd_by_shell.get(sh, "")
        if not cmd.strip():
            p.violations[sh] = [f"{sh} 용 명령이 비어 있음"]
            continue
        bad = check(sh, cmd)
        if bad:
            p.violations[sh] = bad
    return p


def run_one(host: Host, cred, cmd: str, approve, changed=None, *, timeout: int = 60) -> ExecOutcome:  # noqa: ANN001
    """호스트 1대 실행(워커 스레드). 정책은 여기서도 다시 본다 — UI 를 우회해도 쓰기 명령은 못 나간다."""
    from infraguard.ui.workers import build_connection
    sh = shell_for(host)
    out = ExecOutcome(host_id=host.host_id, label=host.label, shell=sh, cmd=cmd)
    bad = check(sh, cmd)
    if bad:
        out.error = "정책 위반: " + "; ".join(bad)
        return out
    started = time.monotonic()
    conn = None
    try:
        conn = build_connection(host, cred, approve, changed)
        conn.connect()
        r = conn.exec(argv_for(sh, cmd), timeout=timeout)
        out.exit_code, out.stdout, out.stderr = r.exit_code, r.stdout or "", r.stderr or ""
        if r.timed_out:
            out.error = f"timeout {timeout}s"
        elif r.error:
            out.error = r.error
    except Exception as e:  # noqa: BLE001
        out.error = f"{type(e).__name__}: {e}"
    finally:
        out.duration_ms = int((time.monotonic() - started) * 1000)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001,S110
                pass
    return out


def write_audit(log_dir: Path, cmd_by_shell: dict[str, str], results: list[ExecOutcome]) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    p = log_dir / f"multiexec_{datetime.now():%Y%m%d_%H%M%S}.log"
    lines = [f"### InfraGuard multi-exec {datetime.now().isoformat(timespec='seconds')}"]
    lines += [f"### [{sh}] {cmd}" for sh, cmd in cmd_by_shell.items()]
    for r in results:
        lines.append(f"--- {r.label} rc={r.exit_code} {r.duration_ms}ms" + (f" ERROR={r.error}" if r.error else ""))
        lines.append(mask(r.stdout) or "")
        if r.stderr.strip():
            lines.append("[stderr] " + (mask(r.stderr) or ""))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def render_text(cmd_by_shell: dict[str, str], results: list[ExecOutcome]) -> str:
    out = [f"[{sh}] {cmd}" for sh, cmd in cmd_by_shell.items()] + [""]
    for r in results:
        out.append(f"===== {r.label} (rc={r.exit_code}, {r.duration_ms}ms)" + (f" ERROR: {r.error}" if r.error else ""))
        out.append((r.stdout or r.stderr).rstrip() or "(출력 없음)")
        out.append("")
    return "\n".join(out)


# ------------------------------------------------------------------ 명령 라이브러리
@dataclass(slots=True)
class Entry:
    category: str
    name: str
    commands: dict[str, str]        # shell → cmd (sh/powershell/raw 중 있는 것만)
    user: bool = False

    def for_shell(self, shell: str) -> str | None:
        return self.commands.get(shell)


def _entries_from(raw: Any, user: bool) -> list[Entry]:
    out: list[Entry] = []
    for cat, items in (raw or {}).items():
        for it in items or []:
            cmds = {k: str(v) for k, v in (it or {}).items() if k in ("sh", "powershell", "raw") and v}
            if it.get("name") and cmds:
                out.append(Entry(str(cat), str(it["name"]), cmds, user))
    return out


def load_library(user_raw: dict | None = None) -> list[Entry]:
    """동봉 라이브러리 + 사용자 항목(config `command_library`). 쓰기 명령이 섞여 있으면 그 항목은 버린다."""
    raw = yaml.safe_load(LIBRARY_FILE.read_text(encoding="utf-8")) if LIBRARY_FILE.exists() else {}
    out = _entries_from(raw, False) + _entries_from(user_raw or {}, True)
    return [e for e in out if all(not check(sh, c) for sh, c in e.commands.items())]


def validate_entry(commands: dict[str, str]) -> list[str]:
    """라이브러리 등록 전 검사. 위반 사유 목록(비어 있으면 등록 가능)."""
    bad: list[str] = []
    for sh, c in commands.items():
        if sh not in SHELLS:
            bad.append(f"알 수 없는 셸 {sh}")
            continue
        bad += [f"[{sh}] {w}" for w in check(sh, c)]
    if not commands:
        bad.append("명령이 비어 있음")
    return bad
