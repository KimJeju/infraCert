"""민감정보 마스킹.

진단 결과는 고객사 밖으로 반출된다. 마스킹 실패는 사고로 직결된다.

키 이름 기반만으로는 부족하다. 기존 스크립트 자산은 /etc/shadow 해시,
SNMP community, 계정 목록을 근거(evidence)에 그대로 담는다.
따라서 값 패턴 기반 마스킹을 함께 적용한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MASK = "***MASKED***"


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    repl: str


RULES: tuple[Rule, ...] = (
    Rule(
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "***PRIVATE_KEY***",
    ),
    Rule(
        # /etc/shadow 해시: $1$ $2a$ $5$ $6$ $y$ 등
        "unix_hash",
        re.compile(r"\$[0-9a-zA-Z]{1,3}\$[A-Za-z0-9./$]{12,}"),
        "***HASH***",
    ),
    Rule(
        "aws_key",
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
        "***AWS_KEY***",
    ),
    Rule(
        "jdbc_password",
        re.compile(r"(?i)(jdbc:[^\s;]*?[?;&]password=)(?!\*{2,})[^\s;&\"']+"),
        r"\1***",
    ),
    Rule(
        "kv_secret",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|"
            r"credential|passphrase)\b(\s*[=:]\s*)(?!\*{2,})[^\s,;\"']{1,200}"
        ),
        r"\1\2***",
    ),
    Rule(
        # SNMP community: com2sec <name> <src> <community>
        "snmp_community",
        re.compile(r"(?i)\b(com2sec\s+\S+\s+\S+\s+)(?!\*{2,})(\S+)"),
        r"\1***COMMUNITY***",
    ),
    Rule(
        "snmp_directive",
        re.compile(r"(?i)\b(rocommunity|rwcommunity|community)(\s+)(?!\*{2,})(\S+)"),
        r"\1\2***COMMUNITY***",
    ),
    Rule(
        "bearer",
        re.compile(r"(?i)\b(bearer|authorization:\s*basic)\s+(?!\*{2,})[A-Za-z0-9._\-+/=]{8,}"),
        r"\1 ***",
    ),
)


def mask(text: str | None) -> str | None:
    """모든 규칙을 적용한다. 규칙 하나가 실패해도 나머지는 계속 적용된다."""
    if not text:
        return text
    out = text
    for r in RULES:
        try:
            out = r.pattern.sub(r.repl, out)
        except re.error:  # pragma: no cover
            continue
    return out


def mask_all(values: dict[str, str]) -> dict[str, str]:
    return {k: (mask(v) or "") for k, v in values.items()}


def find_unmasked(text: str) -> list[str]:
    """마스킹 회귀 테스트용. 남아있는 민감 패턴 이름 목록."""
    hits: list[str] = []
    for r in RULES:
        if r.pattern.search(text):
            hits.append(r.name)
    return hits
