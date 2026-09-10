# worklog — 작업 리포트 (Cowork ↔ Claude Code 공유)

매 작업 세션마다 무엇을·왜·결과를 md 로 남긴다. toss_trader 의 worklog 관례를 그대로 쓴다.

## 규칙
- 파일명: `YYYY-MM-DD.md` (하루 여러 세션이면 같은 날짜 파일에 `## 세션 N` 로 append).
- 담당 표기: **[CC]**=Claude Code(로컬) / **[C]**=Cowork(클라우드) / **[형]**=사람.
- 구성: 요약 3줄 → 한 일(무엇·왜·결과) → 열린 항목/다음 → 형 확인필요(🔴).
- 고객사 서버·크리덴셜을 건드리는 결정은 항상 🔴 로 표시.
- 원격: `https://github.com/KimJeju/infraCert.git` (public). 작업 끝나면 커밋 + push.
- `rulepacks/kisa-2026/scripts/` 는 고객 프로젝트 파생이라 **커밋하지 않는다**(로컬 전용). manifest 는 참조만 유지.

## 색인
- [2026-09-09](2026-09-09.md) — [CC] UI 전 단계(U-1~U-9)·룰팩·네이티브 SSH 룰(B안)·텍스트리포트 파서·WSL E2E·터미널/SFTP·디자인·각진 테마
