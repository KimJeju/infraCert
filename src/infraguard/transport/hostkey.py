"""SSH 호스트키 정책.

AutoAddPolicy 를 쓰지 않는다. 중간자 공격 탐지 경로를 없애면 안 된다.
고객사 PC 에 known_hosts 파일을 남기지 않기 위해 승인 결과는 세션 메모리에만 둔다.

키가 바뀐 경우(기존 ≠ 현재)는 기본 **접속 중단**이다. on_changed 콜백이 주어지면 사용자에게
기존/현재 지문을 나란히 보여주고 "기존 키 제거 후 재등록" 을 고를 수 있다(보안진단 도구는 일반 SSH 클라이언트보다 더 명확히).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Protocol

import paramiko

from infraguard.transport.base import HostKeyRejected


class ApprovalCallback(Protocol):
    def __call__(self, host: str, key_type: str, fingerprint: str) -> bool: ...


class ChangedCallback(Protocol):
    def __call__(self, host: str, key_type: str, old_fp: str, new_fp: str) -> bool: ...


def fingerprint_sha256(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


SESSION_KNOWN: dict[str, str] = {}   # host -> fingerprint. 프로세스(=세션) 수명. 디스크에 쓰지 않는다.


class SessionHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """미등록 호스트키를 사용자에게 확인받는다. 승인분은 메모리에만 유지(기본 SESSION_KNOWN 공유)."""

    def __init__(self, approve: ApprovalCallback | None = None,
                 on_changed: ChangedCallback | None = None, store: dict[str, str] | None = None) -> None:
        self._approve: ApprovalCallback | None = approve
        self._on_changed: ChangedCallback | None = on_changed
        self.approved: dict[str, str] = SESSION_KNOWN if store is None else store

    def forget(self, host: str) -> None:
        self.approved.pop(host, None)

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        fp = fingerprint_sha256(key)
        known = self.approved.get(hostname)
        if known == fp:
            return
        if known is not None and known != fp:
            if self._on_changed is not None and self._on_changed(hostname, key.get_name(), known, fp):
                self.approved[hostname] = fp        # 사용자가 명시적으로 재등록
                return
            raise HostKeyRejected(
                f"{hostname}: 호스트키가 이전과 다릅니다 (기존 {known} / 현재 {fp}) — 접속 중단"
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
