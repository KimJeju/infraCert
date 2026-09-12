"""네이티브 룰(B안) — PC측 파이썬이 SSH 로 원시 명령만 실행해 점검한다.

대상 서버에 아무것도 올리지 않는다. 각 룰은 NativeOutcome(원문 판정 어휘 + 근거)만 돌려주고,
Status 확정은 result.engine → core.decision.decide() 가 한다. 룰이 Status 를 직접 만들지 않는다.

룰 코드는 앱에 동봉된다(rulepacks/ 의 데이터 디렉터리에서 임의 파이썬을 로드하지 않는다).
룰팩 manifest 는 impl 이름으로 이 레지스트리를 참조만 한다.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from infraguard.core.models import RemoteEnvironment
from infraguard.transport.base import Connection


@dataclass(slots=True)
class NativeOutcome:
    verdict_raw: str            # GOOD | VULN | MANUAL | NA  (verdict_map 이 매핑)
    evidence: str = ""
    warnings: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)   # 선언형: extracted / matched — provenance 에 합쳐진다


@dataclass(frozen=True, slots=True)
class NativeRule:
    rule_id: str
    name: str
    severity: str               # 상 | 중 | 하
    platforms: tuple[str, ...]  # linux | aix | solaris | hpux ...
    check: Callable[[Connection, RemoteEnvironment], NativeOutcome]
    collects: tuple[tuple[str, str], ...] = ()   # (shell, cmd) — 선언형 룰의 수집 명령. 배치 프리페치용(파이썬 룰은 빈 튜플)


REGISTRY: dict[str, NativeRule] = {}


def register(rule_id: str, name: str, severity: str, platforms: tuple[str, ...]):  # noqa: ANN201
    def deco(fn: Callable[[Connection, RemoteEnvironment], NativeOutcome]):  # noqa: ANN202
        REGISTRY[rule_id] = NativeRule(rule_id, name, severity, platforms, fn)
        return fn
    return deco


def load_all() -> dict[str, NativeRule]:
    """동봉 룰 모듈을 import 해 레지스트리를 채운다."""
    from infraguard.rules import unix  # noqa: F401 - 등록 부수효과
    return REGISTRY
