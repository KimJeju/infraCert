"""KISA 2026 상세가이드 PDF → 플랫폼/제품별 YAML(+JSON) 추출기.

사용:
    python scripts/extract_guide.py <가이드.pdf> [출력 디렉터리]

항목 1건 = id/name/severity/section/category + 점검내용·목적·위협·참고·대상·판단기준·조치·영향
+ procedures(플랫폼별 점검·조치 사례, `[태그]Step 1)` 로 시작하는 변형은 variants 로 분리).
출력은 <섹션 슬러그>/<플랫폼 슬러그>.yaml — 한 항목이 여러 플랫폼을 다루면 각 파일에 모두 들어간다.
PDF 텍스트 추출 특성상 표·그림 캡션 순서가 뒤섞인 항목이 있어 원문 대조는 `pages` 로 한다.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

# ---------------------------------------------------------------- 섹션/플랫폼 정의
SECTIONS = {  # id 접두 → (섹션 라벨(헤더 원문), 출력 디렉터리)
    "U": ("UNIX", "unix"),
    "W": ("Windows 서버", "windows"),
    "WEB": ("웹 서비스", "web-service"),
    "S": ("보안 장비", "security-device"),
    "N": ("네트워크 장비", "network"),
    "C": ("제어시스템", "control-system"),
    "PC": ("PC", "pc"),
    "D": ("DBMS", "dbms"),
    "M": ("이동통신", "mobile"),
    "HV": ("가상화 장비", "virtualization"),
    "CA": ("클라우드", "cloud"),
}
WEBAPP_DIR = "web-application"

# 플랫폼 불릿(원문은 글머리 기호가 'l' 로 추출됨). 토큰 → 파일 슬러그.
PLATFORM_SLUG = {
    "공통": "common",
    "SOLARIS": "solaris", "LINUX": "linux", "AIX": "aix", "HP-UX": "hpux",
    "Tomcat": "tomcat", "JEUS": "jeus", "IIS": "iis", "Apache": "apache", "Nginx": "nginx", "WebtoB": "webtob",
    "Cisco IOS": "cisco-ios", "Juniper Junos": "juniper-junos", "Juniper": "juniper-junos",
    "Radware Alteon": "radware-alteon", "Passport": "passport", "Piolink PLOS": "piolink-plos",
    "Oracle DB": "oracle", "OracleDB": "oracle", "MSSQL": "mssql", "MySQL": "mysql", "Altibase": "altibase",
    "Tibero": "tibero", "PostgreSQL": "postgresql", "Cubrid": "cubrid",
    "VMware ESXi": "vmware-esxi", "VMware vCenter": "vmware-vcenter", "vCenter": "vmware-vcenter",
    "XenServer": "xenserver", "KVM": "kvm", "Nutanix": "nutanix",
}
# 불릿 시작 판별용 — 위 키 + Windows 계열 + 공통. 긴 이름 먼저.
_PAREN = r"(?:\s*\([^()\n]{0,40}\))?"  # 'SOLARIS(5.9 이하 버전)', 'NT(IIS 4.0)' 같은 주석
_WINTOK = r"(?:NT[A-Z]?|2000|2003|2008|2012|2016|2019|2022|10|11|OS)" + _PAREN
_WIN = r"Windows? " + _WINTOK + r"(?:,\s*(?:Windows )?" + _WINTOK + r")*"
_NAMES = sorted(PLATFORM_SLUG, key=len, reverse=True)
_ONE = "(?:" + "|".join(re.escape(n) for n in _NAMES) + ")" + _PAREN
_ONE = "(?:" + _ONE + "|" + _WIN + ")"
BULLET_RE = re.compile(
    r"l ?(?P<plat>" + _ONE + r"(?:\s*(?:,|/)\s*" + _ONE + r")*)" + _PAREN + r"\s*(?=\[|Step ?\d|- 점검|$)", re.M
)
# 플랫폼이 아닌 기법별 불릿(웹앱 'lLDAP 인젝션- 점검 방법', 보안장비 'lFlooding 공격Step 1)') — 줄 첫머리/사례 직후만
TECH_BULLET_RE = re.compile(r"(?m)(?:^|(?<=사례)|(?<=\]))l ?(?P<plat>[^\n\[]{2,60}?)\s*(?=- 점검 방법|Step ?1\))")
# 배포판 변형 → 별도 파일도 만든다(예: unix/linux-redhat.yaml)
DISTRO_TAGS = {"Redhat": "redhat", "RedHat": "redhat", "Debian": "debian", "Ubuntu": "ubuntu",
               "CentOS": "centos", "Rocky": "rocky", "SUSE": "suse"}

# ---------------------------------------------------------------- 필드 라벨
FIELDS = [  # (라벨 원문, 키). 순서 무관 — 위치로 자른다.
    ("점검 내용", "check"),
    ("점검 목적", "purpose"),
    ("보안 위협", "threat"),
    ("참고", "reference"),
    ("상세 설명", "detail"),
    ("점검 대상 및 판단 기준", "_targets_hdr"),
    ("대상", "targets"),
    ("판단 기준", "_judge_hdr"),
    ("양호 :", "good"),
    ("취약 :", "vuln"),
    ("조치 방법", "remediation"),
    ("조치 시 영향", "impact"),
    ("점검 및 조치 사례", "procedures"),
]
_LABEL_RE = re.compile("|".join(re.escape(lbl) for lbl, _ in FIELDS))
_LABEL_KEY = dict(FIELDS)

HDR_RE = re.compile(
    r"(?m)^\s*(?P<id>(?:U|W|WEB|S|N|C|PC|D|M|HV|CA)-\d{2})\((?P<sev>상|중|하)\)\s*"
    r"(?P<section>[^>\n]{1,25}?)\s*>\s*(?P<rest>[^\n]+)"
)
WEBAPP_HDR_RE = re.compile(
    r"(?m)^\s*(?P<id>[A-Z]{2})\((?P<sev>상|중|하)\)\s*Web Application\(웹\)(?P<rest>\d+\.[^\n]{1,80}?)개요"
)
PAGE_HDR_RE = re.compile(r"^\s*(?:\| 한국인터넷진흥원 \||\d{2}\. [^\n]*?상세가이드)\s*\n\s*\d+\s*\n")


# ---------------------------------------------------------------- 텍스트 추출
def pdf_pages(path: Path) -> list[str]:
    if path.suffix.lower() == ".txt":  # 사전 추출본(===== PAGE n ===== 구분)
        raw = path.read_text(encoding="utf-8")
        return [p.split(" =====\n", 1)[1] for p in raw.split("\n===== PAGE ")[1:]]
    import pypdf  # noqa: PLC0415

    reader = pypdf.PdfReader(str(path))
    return [(p.extract_text() or "") for p in reader.pages]


def toc_categories(pages: list[str]) -> dict[str, list[str]]:
    """목차(3~6쪽)에서 챕터별 분류명. 'I. Unix 서버 ··· 7  1. 계정 관리 ··· 12' 형태."""
    toc = re.sub(r"(?:·\s?)+", " … ", "\n".join(pages[2:6]))
    cats: dict[str, list[str]] = {}
    cur = None
    for m in re.finditer(r"(?:(?P<ch>[IVX]+|[Ⅰ-Ⅻ])\.\s*(?P<chname>[^…\d][^…]*?)\s*…|(?P<n>\d+)\.\s*(?P<cat>[^…\d][^…]*?)\s*…)", toc):
        if m.group("ch"):
            cur = m.group("chname").strip()
            cats[cur] = []
        elif cur:
            cats[cur].append(m.group("cat").strip())
    return cats


def strip_page_chrome(txt: str) -> str:
    return PAGE_HDR_RE.sub("", txt, count=1)


def build_body(pages: list[str]) -> tuple[str, list[int]]:
    """페이지 합치고 각 문자 오프셋 → 페이지 번호 맵(누적 시작 오프셋)."""
    parts, starts, pos = [], [], 0
    for p in pages:
        t = strip_page_chrome(p) + "\n"
        starts.append(pos)
        parts.append(t)
        pos += len(t)
    return "".join(parts), starts


def page_of(starts: list[int], off: int) -> int:
    import bisect  # noqa: PLC0415

    return bisect.bisect_right(starts, off)


# ---------------------------------------------------------------- 항목 파싱
def split_fields(text: str) -> dict[str, str]:
    """라벨 위치로 잘라 필드 dict. 순서가 뒤섞여도(표 추출 순서) 라벨 기준으로 복구."""
    hits = [(m.start(), m.end(), _LABEL_KEY[m.group(0)]) for m in _LABEL_RE.finditer(text)]
    out: dict[str, str] = {}
    hits.sort()
    cleaned: list[tuple[int, int, str]] = []
    last_end = -1
    for s, e, k in hits:
        if s < last_end:  # '점검 대상 및 판단 기준' 안의 '대상' 등 겹침
            continue
        after = text[e:e + 6]
        before = text[max(0, s - 2):s]
        if k == "targets" and not (cleaned and cleaned[-1][2] == "_targets_hdr" and cleaned[-1][1] == s):
            continue  # 본문 속 '대상 시스템…' 은 라벨 아님
        if k == "_judge_hdr" and not re.match(r"\s*양호", after):
            continue
        if k == "remediation" and before.strip().endswith("-"):
            continue  # 웹앱 사례 안의 '- 조치 방법'
        if k == "reference" and not re.match(r"(?:※|-|\s|상세|점검|$)", after):
            continue  # '참고하여' 등
        if k == "detail" and not after.startswith("§"):
            continue  # 이동통신 항목의 '상세 설명§…' 만. 웹앱 표 머리글 '구분 상세 설명' 제외
        cleaned.append((s, e, k))
        last_end = e
    for i, (_s, e, k) in enumerate(cleaned):
        nxt = cleaned[i + 1][0] if i + 1 < len(cleaned) else len(text)
        val = text[e:nxt].strip()
        if k.startswith("_"):
            continue
        out[k] = (out[k] + "\n" + val).strip() if k in out and val else out.get(k, val)
    return out


STEP_RE = re.compile(r"\s*Step ?(\d+)\)\s*")


def split_steps(block: str) -> dict:
    """'Step N)' 로 나눠 steps 리스트. 앞부분은 intro. 그림 캡션 '[ ... ]' 은 figures."""
    figs = re.findall(r"\[ ([^\[\]\n]{2,60}) \]", block)
    block = re.sub(r"\[ [^\[\]\n]{2,60} \]", "", block)
    parts = STEP_RE.split(block)
    d: dict = {}
    intro = parts[0].strip()
    if intro:
        d["intro"] = intro
    steps = []
    for i in range(1, len(parts), 2):
        steps.append(f"Step {parts[i]}) {parts[i + 1].strip()}")
    if steps:
        d["steps"] = steps
    if figs:
        d["figures"] = figs
    return d


VARIANT_RE = re.compile(r"\[([^\[\]\n]{2,40})\]\s*(?=Step ?1\))")


def split_variants(block: str) -> dict:
    """'[태그]Step 1)' 로 시작하는 변형(Telnet/SSH, Redhat/Debian, 메일서버별…) 분리."""
    hits = list(VARIANT_RE.finditer(block))
    if not hits:
        return split_steps(block)
    d: dict = {}
    head = block[: hits[0].start()].strip()
    if head:
        d.update(split_steps(head))
    variants: dict[str, dict] = {}
    for i, m in enumerate(hits):
        nxt = hits[i + 1].start() if i + 1 < len(hits) else len(block)
        tag = m.group(1).strip()
        body = block[m.end():nxt]
        key = tag
        n = 2
        while key in variants:  # 같은 태그 반복(예: [Telnet] 두 번)
            key = f"{tag} #{n}"
            n += 1
        variants[key] = split_steps(body)
    d["variants"] = variants
    return d


def platform_tokens(label: str) -> list[str]:
    toks = [re.sub(r"\s*\([^()]*\)", "", t).strip() for t in re.split(r",|/", label) if t.strip()]
    out = []
    for t in toks:
        if re.fullmatch(r"(?:Windows )?(?:NT|2000|2003|2008|2012|2016|2019|2022|10|11|OS)", t) or t.startswith("Window"):
            out.append("windows")
        else:
            out.append(PLATFORM_SLUG.get(t, re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")))
    return list(dict.fromkeys(out))


def split_procedures(text: str) -> list[dict]:
    hits = list(BULLET_RE.finditer(text))
    tech = False
    if not hits:  # 플랫폼 불릿이 없으면 기법 불릿(웹앱·보안장비) — 파일 분류는 common
        hits, tech = list(TECH_BULLET_RE.finditer(text)), True
    if not hits:
        return [{"platform": "(미구분)", "slugs": ["common"], **split_variants(text)}] if text.strip() else []
    procs = []
    lead = text[: hits[0].start()].strip()
    if lead:
        procs.append({"platform": "(미구분)", "slugs": ["common"], **split_variants(lead)})
    for i, m in enumerate(hits):
        nxt = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        label = re.sub(r"\s+", " ", m.group("plat")).strip()
        body = text[m.end():nxt]
        procs.append({"platform": label, "slugs": ["common"] if tech else platform_tokens(label), **split_variants(body)})
    return procs


def parse_item(hdr: re.Match, body: str, cats: list[str], webapp: bool) -> dict:
    rest = hdr.group("rest")
    if webapp:
        category = rest.strip()
        name = re.sub(r"^\d+\.\s*", "", category)
        if hdr.group("id") == "CC" and "자동화" in name:  # 본문 헤더 오타 — 항목표(p678)는 AU
            hdr_id_override = "AU"
        section = "Web Application(웹)"
        item_body = body[hdr.end():]
    else:
        section = hdr.group("section").strip()
        # rest = '1. 계정 관리root 계정 원격 접속 제한개요점검 내용...' → 분류명은 목차 기준 최장 접두
        category, name = None, None
        for c in sorted(cats, key=len, reverse=True):
            m = re.match(r"(\d+)\.\s*" + re.escape(c), rest)
            if m:
                category = f"{m.group(1)}. {c}"
                name = rest[m.end():]
                break
        if category is None:  # 목차에 없는 분류 — '관리' 까지를 분류로 추정
            m = re.match(r"(\d+\.\s*.+?관리)", rest)
            category = m.group(1) if m else rest
            name = rest[m.end():] if m else ""
        name = name.split("개요", 1)[0].strip()
        item_body = body[hdr.start() + len(hdr.group(0)) - len(rest) + rest.find("개요"):] if "개요" in rest else body[hdr.end():]
    fields = split_fields(item_body)
    item = {
        "id": locals().get("hdr_id_override") or hdr.group("id"),
        "name": name,
        "severity": hdr.group("sev"),
        "section": section,
        "category": category,
    }
    for k in ("check", "purpose", "threat", "reference", "detail", "targets"):
        if k in fields:
            item[k] = fields[k]
    if "good" in fields or "vuln" in fields:
        item["judgment"] = {k: fields[k] for k in ("good", "vuln") if k in fields}
    for k in ("remediation", "impact"):
        if k in fields:
            item[k] = fields[k]
    item["procedures"] = split_procedures(fields.get("procedures", ""))
    return item


def parse(pages: list[str]) -> list[dict]:
    body, starts = build_body(pages)
    toc = toc_categories(pages)
    # 섹션 라벨 → 목차 분류 (목차 챕터명과 헤더 라벨이 달라 느슨히 매핑)
    def cats_for(label: str) -> list[str]:
        for ch, cs in toc.items():
            if label.replace(" ", "") in ch.replace(" ", "") or ch.replace(" ", "") in label.replace(" ", ""):
                return cs
        if label == "UNIX":
            return toc.get("Unix 서버", [])
        return []

    heads = [(m.start(), m, False) for m in HDR_RE.finditer(body)]
    heads += [(m.start(), m, True) for m in WEBAPP_HDR_RE.finditer(body)]
    heads.sort(key=lambda x: x[0])
    items = []
    for i, (pos, _m, webapp) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(body)
        chunk = body[pos:end]
        # 헤더 매치를 chunk 기준으로 다시 잡는다
        hm = (WEBAPP_HDR_RE if webapp else HDR_RE).match(chunk)
        label = "Web Application(웹)" if webapp else hm.group("section").strip()
        item = parse_item(hm, chunk, cats_for(label), webapp)
        item["pages"] = [page_of(starts, pos), page_of(starts, end - 1)]
        items.append(item)
    return items


# ---------------------------------------------------------------- 출력
def section_dir(item: dict) -> str:
    if item["section"] == "Web Application(웹)":
        return WEBAPP_DIR
    return SECTIONS[item["id"].split("-")[0]][1]


def yaml_dump(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(obj, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")


def emit(items: list[dict], out: Path) -> dict:
    by_file: dict[tuple[str, str], list[dict]] = defaultdict(list)
    by_section: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        sec = section_dir(it)
        by_section[sec].append(it)
        seen: set[str] = set()
        for p in it["procedures"]:
            for slug in p["slugs"]:
                # 플랫폼 파일에는 그 플랫폼 절차만 싣는다
                if slug in seen:
                    continue
                seen.add(slug)
                sub = dict(it)
                sub["procedures"] = [q for q in it["procedures"] if slug in q["slugs"]]
                by_file[(sec, slug)].append(sub)
                # 배포판 변형 파일(linux-redhat 등)
                for q in sub["procedures"]:
                    for tag, dslug in DISTRO_TAGS.items():
                        v = (q.get("variants") or {}).get(tag)
                        if v is None:
                            continue
                        d = dict(sub)
                        d["procedures"] = [{"platform": f"{q['platform']} [{tag}]", "slugs": [f"{slug}-{dslug}"], **v}]
                        by_file[(sec, f"{slug}-{dslug}")].append(d)
    index: dict = {"source": "KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)", "files": []}
    for (sec, slug), lst in sorted(by_file.items()):
        # 같은 항목이 두 번 들어간 경우(배포판 파일) 중복 제거
        uniq = list({x["id"]: x for x in lst}.values())
        yaml_dump({"section": lst[0]["section"], "platform": slug, "count": len(uniq), "items": uniq}, out / sec / f"{slug}.yaml")
        index["files"].append({"path": f"{sec}/{slug}.yaml", "count": len(uniq)})
    for sec, lst in sorted(by_section.items()):
        yaml_dump({"section": lst[0]["section"], "count": len(lst), "items": lst}, out / sec / "_all.yaml")
        index["files"].append({"path": f"{sec}/_all.yaml", "count": len(lst)})
    (out / "all.json").write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    yaml_dump(index, out / "index.yaml")
    return index


def report(items: list[dict]) -> None:
    c = Counter(section_dir(i) for i in items)
    print("items:", len(items), dict(c))
    missing = Counter()
    for i in items:
        for k in ("check", "purpose", "threat", "targets", "judgment", "remediation", "impact"):
            if k not in i:
                missing[k] += 1
        if not i["procedures"]:
            missing["procedures"] += 1
    print("missing:", dict(missing))
    plats = Counter(s for i in items for p in i["procedures"] for s in p["slugs"])
    print("platform slugs:", dict(plats))
    unk = [(i["id"], p["platform"]) for i in items for p in i["procedures"] if p["platform"] == "(미구분)"]
    print("unlabelled procedure blocks:", len(unk), unk[:15])


def main(argv: list[str]) -> int:
    src = Path(argv[1])
    out = Path(argv[2]) if len(argv) > 2 else Path("rulepacks/kisa-2026/guide")
    items = parse(pdf_pages(src))
    report(items)
    idx = emit(items, out)
    print("files:", len(idx["files"]), "->", out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
