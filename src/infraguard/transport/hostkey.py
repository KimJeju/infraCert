"""SSH 호스트키 정책.

AutoAddPolicy 를 쓰지 않는다. 중간자 공격 탐지 경로를 없애면 안 된다.
고객사 PC 에 known_hosts 파일을 남기지 않기 위해 승인 결과는 세션 메모리에만 둔다.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Callable, Protocol

import paramiko

from infraguard.transport.base import HostKeyRejected


class ApprovalCallback(Protocol):
    def __call__(self, host: str, key_type: str, fingerprint: str) -> bool: ...


def fingerprint_sha256(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class SessionHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """미등록 호스트키를 사용자에게 확인받는다. 승인분은 메모리에만 유지."""

    def __init__(self, approve: ApprovalCallback | None = None) -> None:
        self._approve: ApprovalCallback | None = approve
        self.approved: dict[str, str] = {}   # host -> fingerprint

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        fp = fingerprint_sha256(key)
        known = self.approved.get(hostname)
        if known == fp:
            return
        if known is not None and known != fp:
            raise HostKeyRejected(
                f"{hostname}: 호스트키가 이전과 다릅니다 (기존 {known} / 현재 {fp})"
            )
        if self._approve is None:
            raise HostKeyRejected(
                f"{hostname}: 미등록 호스트키 {key.get_name()} {fp} — 승인 절차 없음"
            )
        if not self._approve(hostname, key.get_name(), fp):
            raise HostKeyRejected(f"{hostname}: 사용자가 호스트키를 거부했습니다 ({fp})")
        self.approved[hostname] = fp


def auto_approve_for_tests() -> ApprovalCallback:
    """테스트 전용. 운영 코드에서 호출 금지."""
    def _cb(host: str, key_type: str, fingerprint: str) -> bool:  # noqa: ARG001
        return True
    return _cb
