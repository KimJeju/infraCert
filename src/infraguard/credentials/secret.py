"""평문 비밀정보 래퍼.

고객사 PC 에서 구동되므로 평문이 디스크·로그·직렬화 경로로 새면 사고다.
타입 수준에서 유출 경로를 차단한다.

reveal() 호출은 transport 계층으로 한정한다.
(tests/failure/test_secret_leak.py 에서 호출 지점을 검증한다)
"""

from __future__ import annotations

from typing import Any, NoReturn

_MASK = "***"


class Secret:
    """문자열처럼 보이지만 절대 평문을 내놓지 않는 래퍼."""

    __slots__ = ("_v",)

    def __init__(self, value: str) -> None:
        self._v = value

    # --- 유출 경로 차단 -------------------------------------------------
    def __repr__(self) -> str:
        return f"Secret({_MASK})"

    def __str__(self) -> str:
        return _MASK

    def __format__(self, _spec: str) -> str:
        return _MASK

    def __reduce__(self) -> NoReturn:
        # pickle/copy 경로로 평문이 체크포인트·큐·로그에 실리는 것을 막는다.
        raise TypeError("Secret is not serializable")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Secret is not serializable")

    def __deepcopy__(self, _memo: dict[int, Any]) -> Secret:
        # 복사는 허용하되 새 래퍼로만.
        return Secret(self._v)

    # --- 비교 -----------------------------------------------------------
    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._v == other._v
        return NotImplemented

    def __hash__(self) -> int:
        # 해시가 평문을 유추할 근거가 되지 않도록 길이만 반영한다.
        return hash(("Secret", len(self._v)))

    def __bool__(self) -> bool:
        return bool(self._v)

    def __len__(self) -> int:
        return len(self._v)

    # --- 유일한 노출 지점 -------------------------------------------------
    def reveal(self) -> str:
        """평문 반환. transport 계층에서만 호출한다."""
        return self._v

    def clear(self) -> None:
        """참조를 끊는다.

        CPython 에서 str 은 불변이라 메모리 즉시 소거는 보장할 수 없다.
        이 한계를 문서화하고, 수명 단축만을 목적으로 한다.
        """
        self._v = ""
