"""진단 세션 패키지 — 현장 PC 에서 내보내 사무실 PC 에서 이어서 본다.

포함: session.json(엔진·룰팩 정체·시각), assets.json(호스트 인벤토리), exceptions.json, results/<scan_id>.json,
      audit/(터미널 감사 기록·마스킹 완료분). **크리덴셜은 구조적으로 들어갈 수 없다**(Host 모델에 없다).
가져오기는 zip 멤버 이름을 화이트리스트로만 받는다(경로 이탈 차단).
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from infraguard.assets.exceptions import RiskException
from infraguard.assets.models import Host
from infraguard.assets.store import AssetStore
from infraguard.core.models import ScanResult
from infraguard.orchestrator.results_store import ResultsStore

FORMAT = 1
_SCAN_MEMBER = re.compile(r"^results/([A-Za-z0-9_.-]+)\.json$")
_AUDIT_MEMBER = re.compile(r"^audit/([A-Za-z0-9_.-]+)$")


@dataclass(slots=True)
class ImportSummary:
    hosts: int = 0
    scans: int = 0
    exceptions: int = 0
    audit_files: int = 0
    session: dict = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)


def export_session(out: Path, *, assets: AssetStore, results: ResultsStore, engine_version: str,
                   rulepack: dict | None = None, audit_dir: Path | None = None,
                   scan_ids: list[str] | None = None) -> Path:
    ids = scan_ids if scan_ids is not None else [sid for sid, _ in results.list_scans()]
    session = {"format": FORMAT, "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
               "engine_version": engine_version, "rulepack": rulepack or {}, "scans": ids}
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("session.json", json.dumps(session, ensure_ascii=False, indent=1))
        zf.writestr("assets.json", json.dumps([h.model_dump(mode="json") for h in assets.all()],
                                              ensure_ascii=False, indent=1))
        zf.writestr("exceptions.json", json.dumps([e.model_dump(mode="json") for e in assets.all_exceptions()],
                                                  ensure_ascii=False, indent=1))
        for sid in ids:
            scan = results.load_scan(sid)
            if scan is not None:
                zf.writestr(f"results/{sid}.json", scan.model_dump_json(indent=1))
        if audit_dir and audit_dir.exists():
            for f in sorted(audit_dir.iterdir()):
                if f.is_file() and not f.is_symlink() and f.suffix in (".log", ".txt"):
                    zf.write(f, f"audit/{f.name}")
    return out


def import_session(src: Path, *, assets: AssetStore, results: ResultsStore,
                   audit_dir: Path | None = None) -> ImportSummary:
    s = ImportSummary()
    with zipfile.ZipFile(src) as zf:
        names = set(zf.namelist())
        if "session.json" not in names:
            raise ValueError("session.json 없음 — InfraGuard 세션 패키지가 아닙니다")
        s.session = json.loads(zf.read("session.json"))
        if int(s.session.get("format", 0)) > FORMAT:
            raise ValueError(f"패키지 형식 {s.session.get('format')} — 이 버전은 {FORMAT} 까지 읽습니다")
        for h in json.loads(zf.read("assets.json")) if "assets.json" in names else []:
            assets.upsert(Host.model_validate(h))
            s.hosts += 1
        for e in json.loads(zf.read("exceptions.json")) if "exceptions.json" in names else []:
            assets.set_exception(RiskException.model_validate(e))
            s.exceptions += 1
        for n in sorted(names):
            if n in ("session.json", "assets.json", "exceptions.json"):
                continue
            if _SCAN_MEMBER.match(n):
                results.save_scan(ScanResult.model_validate_json(zf.read(n)))
                s.scans += 1
            elif (m := _AUDIT_MEMBER.match(n)) and audit_dir is not None:
                audit_dir.mkdir(parents=True, exist_ok=True)
                (audit_dir / m.group(1)).write_bytes(zf.read(n))
                s.audit_files += 1
            else:
                s.skipped.append(n)          # 화이트리스트 밖 멤버는 건드리지 않는다
    return s
