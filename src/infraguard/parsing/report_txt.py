"""텍스트 리포트 파서 — 자체 제작 KISA 스크립트(aix/oracle/web)의 .txt 산출물.

두 가지 라인 형식을 함께 지원한다(모두 같은 팀 스크립트의 log/emit 헬퍼 산출):

  A) 브래킷형 (aix, result() 헬퍼)
     [양호]  U-01(상)  root 계정 원격 접속 제한
         >> 근거 한 줄
  B) 파이프형 (oracle/web, emit() 헬퍼)
     D-02 | 양호 | 데모/샘플 계정 없음
     WEB-01(tomcat) | 취약 | 관리자 페이지 노출
         >> 근거 (web 의 dt() 헬퍼)

섹션(`===== …`)·요약(`# 점검 요약`)은 무시. 판정 어휘는 verdict_map 이 Status 로 매핑하고
여기서는 원문만 뽑는다. 중복 코드(제품별 WEB-01 등)는 extra["product"] 로 구분한다.
"""

from __future__ import annotations

import re
from pathlib import Path

from infraguard.core.models import RawFinding, SourceInfo
from infraguard.parsing.base import ParseResult

PROFILE = "kisa-report-txt-v1"
ENCODINGS = ("utf-8-sig", "utf-8", "cp949", "euc-kr")

# 판정 어휘는 여기서 제한하지 않는다. 미등록 어휘도 원문 그대로 뽑아 verdict_map 이
# UNKNOWN+경고로 드러내게 한다(라인을 조용히 버리지 않는다). 코드 형식이 앵커 역할을 한다.
BRACKET_RE = re.compile(
    r"^\[(?P<verdict>[^\]]{1,12})\]\s+(?P<code>[A-Z]+-\d+)\((?P<sev>[^)]*)\)\s+(?P<name>.*?)\s*$"
)
PIPE_RE = re.compile(
    r"^(?P<code>[A-Z]+-\d+)(?:\((?P<product>[^)]*)\))?\s*\|\s*(?P<verdict>[^|]{1,12}?)\s*\|\s*(?P<text>.*?)\s*$"
)
DETAIL_RE = re.compile(r"^\s*>>\s?(?P<text>.*)$")
SUMMARY_RE = re.compile(r"^#\s*점검 요약")
SKIP_RE = re.compile(r"(?:\\n)?\s*\[skip\]\s*(?P<why>.+)$", re.I)   # 스크립트가 대상 미지정으로 점검 생략


def _decode(data: bytes) -> tuple[str, str, bool]:
    for enc in ENCODINGS:
        try:
            return data.decode(enc), enc, False
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8(replace)", True


def looks_like_report(data: bytes) -> bool:
    text, _, _ = _decode(data[:65536])
    return any(BRACKET_RE.match(ln.rstrip()) or PIPE_RE.match(ln.rstrip())
               for ln in text.splitlines())


def parse_report_bytes(data: bytes, *, artifact: str = "",
                       bundle_id: str | None = None) -> ParseResult:
    res = ParseResult(profile=PROFILE)
    text, enc, enc_err = _decode(data)
    res.encoding, res.encoding_error = enc, enc_err
    if enc_err:
        res.warnings.append(f"{artifact}: 인코딩 판별 실패, 치환 문자 사용")

    # 스크립트(result()/emit())는 근거(>>)를 먼저 찍고 판정 헤더를 마지막에 찍는다.
    # 따라서 헤더 직전까지 쌓인 >> 라인이 그 헤더의 근거다. (aix·web 실측)
    pending: list[str] = []

    def emit(finding: RawFinding, inline: str | None = None) -> None:
        parts = [inline.strip()] if inline and inline.strip() else []
        parts += [x for x in pending if x]
        finding.evidence_raw = "\n".join(parts).strip() or None
        res.findings.append(finding)
        pending.clear()

    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if SUMMARY_RE.match(line):
            break
        src = SourceInfo(bundle_id=bundle_id, artifact=artifact, profile=PROFILE, line=i)
        m = BRACKET_RE.match(line)
        if m:
            emit(RawFinding(rule_id=m["code"], name=m["name"].strip() or None,
                            severity_raw=m["sev"].strip() or None,
                            verdict_raw=m["verdict"].strip(), source=src))
            continue
        p = PIPE_RE.match(line)
        if p:
            extra = {"product": p["product"].strip()} if p["product"] else {}
            emit(RawFinding(rule_id=p["code"], verdict_raw=p["verdict"].strip(),
                            extra=extra, source=src), inline=p["text"])
            continue
        d = DETAIL_RE.match(line)
        if d:
            pending.append(d["text"].rstrip())
            continue
        s = SKIP_RE.match(line)
        if s:
            res.warnings.append(f"{artifact}: [skip] {s['why'].strip()}")   # 왜 미보고인지 드러낸다
        elif line.startswith("=====") or line.startswith("-----"):
            continue          # 섹션/구분선은 근거 경계가 아니다(구분선 뒤 헤더가 온다)

    if not res.findings:
        skips = [w for w in res.warnings if "[skip]" in w]
        res.error = ("점검이 전부 생략됨 — " + "; ".join(s.split("[skip] ", 1)[1] for s in skips)
                     if skips else "판정 라인을 찾지 못함 (kisa report txt 형식 아님)")
    return res


def parse_report_file(path: Path, **kw: object) -> ParseResult:
    return parse_report_bytes(path.read_bytes(), artifact=path.name, **kw)  # type: ignore[arg-type]
