"""자산 모델.

호스트 인벤토리는 workspace/assets.db 에 저장된다. **비밀번호·키 본문을 담지 않는다.**
계정명·주소·포트 같은 접속 대상 정보만 보유하고, 크리덴셜은 세션 메모리(CredentialSession)에 둔다.
cred_id 로 세션 크리덴셜과 연결한다. 같은 계정을 여러 호스트가 공유하면 cred_id 가 같다.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from infraguard.core.models import Platform


class Host(BaseModel):
    host_id: str
    name: str
    address: str
    port: int = 22
    platform: str = Platform.LINUX
    project: str = "기본"                # 고객사
    group: str = "서버"                  # 분류 (WEB/DB/WAS ...)
    username: str = "root"
    auth_kind: str = "password"          # password | key | agent
    key_path: str | None = None

    # 1단 bastion
    use_bastion: bool = False
    bastion_host: str | None = None
    bastion_port: int = 22
    bastion_user: str | None = None

    # 실행 — 번들 파라미터(환경변수). 예: TOMCAT_HOME=/opt/tomcat, ORACLE_SID=ORCL
    params: dict[str, str] = Field(default_factory=dict)
    timeout: int = 1800
    use_sudo: bool = False

    # 마지막 진단 요약 (트리 배지용) — 판정 결과이지 상태가 아니다
    last_summary: dict[str, int] = Field(default_factory=dict)
    last_scan_id: str | None = None

    @property
    def cred_id(self) -> str:
        """세션 크리덴셜 키. 같은 계정을 공유하면 한 번만 입력받는다.

        ponytail: 계정명+대상 기준. bastion 경유는 target 기준으로만 묶는다.
        같은 username 이라도 서버가 다르면 비밀번호가 다를 수 있어 주소를 포함한다.
        """
        return f"{self.username}@{self.address}:{self.port}"

    @property
    def label(self) -> str:
        return self.name or self.address
