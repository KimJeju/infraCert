# InfraGuard

인프라 진단 실행·표준화 플랫폼. 고객사 PC에 반입해 구동하는 Windows 데스크톱 애플리케이션(portable).

## 현재 상태

UI 명세 U-1~U-9 구현, WSL sshd 상대 E2E(스크립트 번들·네이티브 룰) 검증, 테스트 96개 통과.

| 계층 | 상태 |
|---|---|
| core (status·decision·models·ids) | 완료 |
| credentials (Secret·session) | 완료 |
| workspace (layout·sanitizer) | 완료 |
| transport.ssh (+hostkey·shell·sftp) | 완료 |
| orchestrator (remote_runner·host_scan·native_runner·results_store) | 완료 |
| assets (models·store, assets.db) | 완료 |
| rulepack (manifest 로더: 번들·네이티브·프로파일·무결성·조치형 거부) | 완료 |
| rules (네이티브 Unix 룰 34종: YAML 28 + 파이썬 6, KISA 2026 U-01~U-33·U-64) | 완료 (서비스 U-34~63 확장 중) |
| parsing (legacy_csv 4종 · report_txt 브래킷/파이프 · dispatch) | 완료 |
| result (masking·engine) | 완료 |
| reporting.xlsx / html | 완료 |
| audit.terminal_recorder (입출력 기록·비밀번호 마스킹) | 완료 |
| ui — 대시보드·진단·결과·수동확인·룰팩·설정·터미널(pyte)·SFTP | 완료 |
| 패키징(PyInstaller onedir, U-10) | 미착수 |
| transport.winrm / netdev / db | 미착수 |

## 실행 방식 두 가지 (프로파일로 선택)

- **스크립트 번들**: `rulepacks/kisa-2026/scripts/*.sh` 를 원격 격리 디렉터리에 업로드·nohup 실행 → 산출물 tar 회수 → 파싱. AIX/Oracle/WEB 자산 그대로 사용.
- **네이티브(SSH 직접 점검)**: 대상에 아무것도 올리지 않고 `infraguard/rules/*.py` 가 SSH 로 읽기전용 명령만 실행해 판정. 무잔류에 유리. 판정은 여전히 `decide()` 단일 경로.

두 방식은 한 프로파일에 섞을 수 있다. 결과는 같은 `HostResult` 로 합쳐진다.

### 네이티브 룰 작성 — 선언형 YAML 우선, 파이썬은 분기가 필요할 때만

단순한 "명령 → 정규식 → 비교" 룰은 `rulepacks/<pack>/rules/<ID>.yaml` 로 쓴다. 코드 변경 없이 룰팩만 바꾸면 된다.

```yaml
id: U-09
name: /etc/passwd 파일 소유자 및 권한
severity: 상
platforms: [linux, aix, solaris, hpux]
collect:                                   # 상수 명령만. 변수 치환 없음(인젝션 차단)
  - key: ls
    cmd: "ls -ld /etc/passwd 2>/dev/null | head -1"
extract:                                   # 이름 있는 그룹 → 변수. lines: 로 줄 수도 가능
  - from: ls
    regex: '^(?P<perm>\S{10})\s+\S+\s+(?P<owner>\S+)\s+(?P<group>\S+)'
    missing: NA                            # 미매치 시 판정을 명시 — 추측하지 않는다
verdict:                                   # 위에서 아래로 첫 매치. when 안은 전부 AND
  - when: {owner: {ne: root}}
    then: VULN
  - when: {perm: {mode_le: "644"}}
    then: GOOD
  - else: VULN
evidence: [ls]
note: "기준: 소유자 root, 권한 644 이하"
```

- 연산자 화이트리스트: `eq ne in contains regex exists absent ge le gt lt mode_le`. **문자열 조건식·eval 없음** — 룰팩이 코드 실행 경로가 되지 않는다(정적 테스트 강제).
- 판정 어휘는 `GOOD / VULN / MANUAL / NA` 만. Status 확정은 여전히 `core.decision.decide()`.
- 어느 `when` 에도 안 걸리면 `MANUAL`(추측 금지). 수집값 변수 `<key>`, 성공 여부 `<key>_ok`.
- 룰 파일은 `manifest.yaml` 의 `rule_files` 에 SHA-256 으로 등록돼야 한다. 미등록·불일치는 실행 차단.
- OS 분기·PAM 파싱처럼 선언형으로 어색한 룰은 `src/infraguard/rules/*.py` 에 파이썬으로 두고 같은 id 로 등록한다. 스키마 정본은 `rules/declarative.py` 의 pydantic 모델.

## 로컬 E2E 환경 (WSL)

WSL Ubuntu 에 sshd 를 :2222 로 띄우고 테스트 계정 `igtest` 로 검증했다. (`wsl -u root` 로 설정)
`.wslconfig` 의 `networkingMode=mirrored` 가 실패하면 apt 가 죽으므로 `nat` 으로 둔다.

UI 실행(전용 venv 권장 — anaconda base 는 user-site 를 무시해 설치본을 못 찾는다):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install "PySide6==6.8.1.1"   # 6.11.x 는 QtCore DLL 로드 실패
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m infraguard.app
```

> PySide6 6.11.x 는 이 개발기(Windows 11 / Python 3.13 anaconda)에서 `QtCore` DLL 로드 실패(procedure not found).
> **6.8.1.1 로 고정**한다. PySide6 를 `-e .` 보다 먼저 설치해야 pyproject 의 `>=6.7` 이 6.11 을 끌어오지 않는다.

## 설계 원칙

1. **실행 실패를 진단 실패로 위장하지 않는다.** `Status` 를 만드는 경로는 `core/decision.py` 의
   `decide()` 하나뿐이며, `PASS` 를 반환하는 분기는 마지막 한 줄이다.
   오류 신호가 하나라도 있으면 `PASS` 에 도달할 수 없다.
2. **고객사 PC에 크리덴셜을 남기지 않는다.** 암호화 보관조차 하지 않는다.
   세션 메모리에만 두고 `Secret` 래퍼로 `repr`/`str`/`format`/`pickle` 경로를 차단한다.
3. **고객사 서버에 흔적을 남기지 않는다.** 원격 격리 디렉터리에서 실행하고,
   삭제 후 존재 여부를 검증한다. 실패 시 조용히 넘어가지 않고 경로를 기록한다.
4. **추측하지 않는다.** 미등록 CSV 헤더·미등록 판정 어휘·확인 불가 환경정보는
   기본값으로 채우지 않고 실패시키거나 `UNKNOWN` 으로 드러낸다.

## 개발 환경

```bash
pip install -e ".[dev]"
python -m pytest tests -q
```

## 테스트

실패 케이스 검증을 우선한다.

```
tests/failure/test_no_pass_leak.py          오류가 PASS 로 새지 않는가
tests/failure/test_secret_leak.py           평문 크리덴셜 유출 경로
tests/failure/test_masking.py               증적 마스킹 회귀
tests/failure/test_workspace_containment.py 잔류물·경로 격리
tests/failure/test_remote_path_safety.py    원격 rm 안전장치
tests/failure/test_parser_failures.py       파서 실패 처리
```

## 파서 프로파일 추가

기존 스크립트의 CSV 헤더가 4종 이상으로 갈린다. 코드를 고치지 않고
`src/infraguard/parsing/profiles/*.yaml` 에 프로파일을 추가한다.

```yaml
name: my-csv-v1
format: csv
match:
  header_all: ["항목코드", "점검항목", "중요도", "결과", "코멘트"]
encoding_candidates: [utf-8-sig, utf-8, cp949, euc-kr]
columns:
  rule_id: 항목코드
  name: 점검항목
  severity: 중요도
  verdict: 결과
  evidence: 코멘트
```

프로파일 판별은 필수컬럼(`header_all`) 수가 많은 쪽이 이긴다.
동률이면 추측하지 않고 실패한다.
