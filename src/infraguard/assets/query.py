"""자산 쿼리 — 사이드바 필터 한 줄로 동적 그룹을 만든다(NetBox 태그 + Rudder 동적 그룹 + osquery 식 조건).

문법: 공백으로 나눈 토큰의 AND.
  key=value   key!=value   key=a,b (OR)      키: os|platform, env, crit, role, tag, group, project, owner, name, addr
  그 외 단어  = 이름·주소·그룹·고객사 부분일치 (기존 필터와 호환)
예:  os=linux env=PROD crit=CRITICAL,HIGH tag=dmz     /   "A은행 WEB"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from infraguard.assets.models import Host

KEYS = {"os": "platform", "platform": "platform", "env": "environment", "crit": "criticality", "role": "role",
        "tag": "tags", "group": "group", "project": "project", "owner": "owner", "name": "name", "addr": "address"}
_TOKEN = re.compile(r'"([^"]+)"|(\S+)')


@dataclass(slots=True)
class Query:
    conds: list[tuple[str, bool, set[str]]] = field(default_factory=list)   # (field, negate, values(lower))
    words: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.conds and not self.words

    def matches(self, h: Host) -> bool:
        for fld, neg, vals in self.conds:
            hv = getattr(h, fld, "")
            hvals = {str(x).lower() for x in hv} if isinstance(hv, list) else {str(hv).lower()}
            hit = bool(hvals & vals)
            if hit == neg:
                return False
        if self.words:
            blob = f"{h.name} {h.address} {h.group} {h.project} {h.role} {' '.join(h.tags)}".lower()
            return all(w in blob for w in self.words)
        return True


def parse(text: str) -> Query:
    q = Query()
    for m in _TOKEN.finditer(text or ""):
        tok = (m.group(1) or m.group(2)).strip()
        if not tok:
            continue
        mm = re.fullmatch(r"([A-Za-z_]+)(!?=)(.+)", tok)
        if mm and mm.group(1).lower() in KEYS:
            q.conds.append((KEYS[mm.group(1).lower()], mm.group(2) == "!=",
                            {v.strip().lower() for v in mm.group(3).split(",") if v.strip()}))
        elif mm:
            q.errors.append(f"알 수 없는 키 {mm.group(1)} (가능: {', '.join(sorted(KEYS))})")
        else:
            q.words.append(tok.lower())
    return q


def filter_hosts(hosts: list[Host], text: str) -> list[Host]:
    q = parse(text)
    return [h for h in hosts if q.matches(h)]
