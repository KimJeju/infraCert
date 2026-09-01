# AppSuit-Android 설계 명세

- 문서 유형: 졸업 프로젝트(작품) 설계 명세
- 작성일: 2026-09-02
- 프로젝트: AppSuit-Android — Android 애플리케이션 런타임 자기보호(RASP) SDK
- 저자: 김건휘 (해킹보안학과)

## 1. 개요

### 1.1 목적
Android 애플리케이션을 대상으로 하는 런타임 자기보호(RASP, Runtime Application
Self-Protection) SDK를 개발한다. 상용 제품(예: Stealien AppSuit)이 제공하는 앱 보안
기능 중 핵심에 해당하는 루팅 탐지, 안티디버그, 후킹(Frida) 탐지를 네이티브(NDK/C)
계층에 구현하여 우회 난이도를 높이고, 개발자가 자신의 앱에 손쉽게 통합할 수 있는
라이브러리(AAR) 형태로 제공한다.

### 1.2 산출물 유형
작품(소프트웨어). 평가 기준은 난이도, 제작 과정의 성실성, 결과물의 동작 여부이다.
동작 여부는 데모 앱의 실시간 탐지 대시보드와 테스트 매트릭스 결과로 입증한다.

### 1.3 범위
- 대상 플랫폼: Android 전용
- 전달 방식: SDK(AAR) 우선. APK 래핑 인젝터는 스트레치 목표.
- 코어 탐지 기능(필수): 루팅 탐지, 안티디버그, Frida/후킹 탐지
- 추천 추가 기능: 무결성/서명 검증(리패키징 방어)
- 대상 외: iOS, DAST/SAST 등 별개 제품

## 2. 아키텍처

```
appsuit-android/
├─ sdk/                         # Android 라이브러리 모듈 → AAR 산출물
│  ├─ src/main/kotlin/
│  │  ├─ AppSuit.kt             # 공개 API (init/scan/callback)
│  │  ├─ Config.kt              # 탐지 정책 · 응답 정책
│  │  └─ Threat.kt              # 탐지 결과 타입
│  └─ src/main/cpp/             # NDK 네이티브 코어 (실제 탐지)
│     ├─ jni_bridge.cpp         # JNI 진입점, Kotlin ↔ native
│     ├─ root_detect.c
│     ├─ antidebug.c
│     ├─ frida_detect.c
│     ├─ integrity.c            # (추천) 서명/CRC 검증
│     ├─ obf.h                  # 컴파일타임 XOR 문자열 난독
│     ├─ util.c                 # /proc 파싱, syscall 헬퍼
│     └─ CMakeLists.txt
├─ demo-app/                    # 샘플 앱: 탐지 라이브 대시보드
└─ docs/                        # 계획서 · 중간 · 최종 보고서
```

- 언어: Kotlin(SDK 표면) + C(NDK 코어). 탐지 로직은 전부 네이티브에 두고 Java/Kotlin
  계층은 얇은 브릿지로 한정한다. 이유: Java/Kotlin 바이트코드는 리패키징·후킹으로
  무력화가 쉬운 반면, 네이티브 코드는 우회 난이도가 높다.
- 빌드: Gradle + CMake/NDK.
- 가정: minSdk 24(Android 7.0), targetSdk 최신 안정 버전. ABI는 arm64-v8a, armeabi-v7a.

### 2.1 모듈 경계와 책임
| 모듈 | 책임 | 인터페이스 | 의존 |
|------|------|-----------|------|
| `AppSuit`(Kotlin) | 공개 API, 생명주기, 주기 탐지 스케줄, 콜백 디스패치 | `init/scan/stop` | JNI 브릿지 |
| `jni_bridge`(C++) | Kotlin ↔ native 변환, 결과 집계 | `nativeScan()` | 탐지 모듈들 |
| `root_detect` 등 각 탐지 모듈(C) | 카테고리별 다중 중복 탐지, 점수 반환 | `detect_*() -> score/detail` | `util`, `obf` |
| `util`/`obf`(C) | /proc 파싱, 문자열 난독 | 헬퍼 함수 | 없음 |

각 탐지 모듈은 독립적으로 이해·테스트 가능하도록 단일 카테고리만 담당한다.

## 3. 공개 API (SDK 표면)

- `AppSuit.init(context: Context, config: Config)`
  - 네이티브 초기화, 기대 서명 해시 로드, 백그라운드 주기 탐지 시작
- `AppSuit.scan(): List<Threat>`
  - 온디맨드 1회 스캔. 활성화된 모든 카테고리 검사 후 위협 목록 반환
- `AppSuit.stop()`
  - 주기 탐지 중지
- `Config`
  - `enabledChecks: Set<Check>` — ROOT / DEBUGGER / FRIDA / INTEGRITY
  - `response: ResponsePolicy` — CALLBACK_ONLY / TERMINATE
  - `intervalMs: Long` — 주기 탐지 간격
  - `onThreat: (Threat) -> Unit` — 콜백
- `Threat`
  - `type: ThreatType` (ROOT/DEBUGGER/FRIDA/TAMPER)
  - `severity: Int`
  - `detail: String` — 어떤 지표가 걸렸는지

## 4. 탐지 로직 (네이티브, 카테고리별 다중 중복)

설계 원칙: 카테고리마다 서로 독립적인 지표를 여럿 두어, 공격자가 하나를 우회해도
전체가 무력화되지 않도록 한다. 각 지표는 점수를 반환하고 합산·임계값으로 판정한다.

### 4.1 루팅 탐지
- `su` 바이너리 경로 스캔(PATH 및 일반 경로)
- Magisk 아티팩트: `/sbin/.magisk`, magiskd 프로세스, resetprop 흔적, 마운트 네임스페이스
- 빌드 속성: `ro.debuggable`, `ro.secure`, `test-keys` 태그
- Magisk Manager 등 관리 패키지 존재 여부(PackageManager는 Kotlin 계층에서 조회)
- system 파티션 쓰기 가능 여부 테스트

### 4.2 안티디버그
- `ptrace(PTRACE_TRACEME)` self-attach — 실패 시 이미 트레이스 중
- `/proc/self/status`의 `TracerPid != 0`
- JDWP / `Debug.isDebuggerConnected` + 실행 타이밍 측정
- (스트레치) fork한 워처 프로세스가 본체를 ptrace 선점하여 디버거 부착 차단

### 4.3 Frida/후킹 탐지
- `/proc/self/maps`에서 frida-agent, frida-gadget, gum 관련 라이브러리 스캔
- 스레드명 검사(gum-js-loop, pool-frida 등)
- 기본 Frida 포트(27042/27043) 검사 — 보조 지표(포트 변경 가능하므로)
- (스트레치) 핵심 네이티브 함수의 인라인 훅 체크섬 검증

### 4.4 무결성/서명 검증 (추천)
- PackageManager로 현재 APK 서명 해시 조회(Kotlin) → 네이티브에 난독 저장한 기대값과 비교
- 리패키징/재서명 탐지에 직접적. 기대 서명 해시는 컴파일타임 XOR로 난독하여 코드에 삽입

## 5. 응답 정책
- CALLBACK_ONLY(기본): 위협을 콜백으로 통지, 처리 판단은 앱에 위임
- TERMINATE(옵션): 콜백 후 네이티브에서 프로세스 종료
- 이벤트 로깅: 데모/보고서용으로 탐지 이벤트 기록

## 6. 안티우회 하드닝
상용 대비 차별점이자 난이도 근거.
- 탐지 로직 네이티브 배치(Java 계층 최소화)
- 컴파일타임 XOR 문자열 난독(경로/포트/라이브러리명)
- 카테고리당 중복 지표(하나 우회 ≠ 전체 우회)
- 주기 재검사
- (스트레치) 네이티브 self-integrity, 동적 `RegisterNatives`

## 7. 테스트 / 동작 여부 입증
- demo-app 대시보드: 각 체크의 green/red 실시간 표시
- 테스트 매트릭스:
  | 환경 | 기대 결과 |
  |------|-----------|
  | 클린 단말/에뮬레이터 | 전부 정상 |
  | 루팅(Magisk) 단말 | ROOT 탐지 |
  | Frida 부착 | FRIDA 탐지 |
  | 디버거 부착 | DEBUGGER 탐지 |
  | 리패키징(재서명) APK | TAMPER 탐지 |
- 우회 시도 로그: RootBeer식 우회, Frida 탐지 우회 스크립트를 적용하여 탐지 견고성을
  시연하고, 우회 가능한 지점은 한계로 명시한다.
- 각 탐지 모듈은 자체 검증 루틴(assert 기반 자가 점검)을 최소 하나씩 남긴다.

## 8. 범위 관리 (우선순위)
- 코어(필수): 루팅 · 안티디버그 · Frida 네이티브 3모듈 + Kotlin API + demo-app + 보고서
- 스트레치 1: 무결성/서명 검증
- 스트레치 2: APK 래핑 인젝터(소스 없이 빌드된 APK에 보호 자동 주입·재서명)
- 스트레치 3: 네이티브 self-integrity

## 9. 리스크
- NDK/JNI 빌드 환경 및 실기기 테스트 필요(에뮬레이터만으로는 루팅/후킹 시나리오 제한적)
- 탐지-우회는 본질적으로 창과 방패 — 완전 방어가 아니라 "우회 난이도 상승"이 목표임을
  보고서에 명확히 한다.
- cowork/OneDrive 폴더는 셸 바이너리·git 쓰기가 차단되므로 프로젝트 루트를
  `C:\dev\appsuit-android`로 둔다.

## 10. 참조 매핑
- OWASP MASVS: RESILIENCE 요구사항(MASVS-RESILIENCE) — 루팅/디버그/후킹/무결성 대응
- OWASP MASTG: 안티리버싱 테스트 케이스
- CWE: CWE-693(Protection Mechanism Failure) 등 관련 항목은 보고서에서 세분 매핑
