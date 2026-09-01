# AppCert

Android 애플리케이션 런타임 자기보호(RASP) SDK. 앱 실행 중 **루팅·디버거·Frida 후킹**을
네이티브(C/NDK) 계층에서 탐지하고, 통합 앱에 위협을 통지한다.

> 상태: **설계·구현 계획 완료, 코어 구현 진행 예정.** 상용 SDK 또는 오픈소스로 배포 목표.

## 왜 네이티브인가

탐지 로직을 Kotlin/Java에 두면 리패키징·후킹으로 무력화가 쉽다. AppCert는 탐지 전부를
C/NDK에 두고 Kotlin은 얇은 브릿지·스케줄·콜백만 담당한다. JNI는 동적 `RegisterNatives`로
등록해 심볼명 후킹을 어렵게 하고, 카테고리마다 독립 지표를 다수 두어 하나를 우회해도
전체가 뚫리지 않게 한다.

## 탐지 카테고리 (코어)

| 카테고리 | 지표(요약) |
|----------|-----------|
| 루팅 | su 바이너리 경로, Magisk 아티팩트, 빌드 속성(test-keys 등) |
| 안티디버그 | `/proc/self/status` TracerPid, `ptrace` self-attach |
| Frida/후킹 | `/proc/self/maps` frida 시그니처, 스레드명 |

스트레치: 무결성/서명 검증, APK 래핑 인젝터, 네이티브 self-integrity.

## 통합 (예정 API)

```kotlin
AppCert.init(context, Config(
    enabledChecks = setOf(Check.ROOT, Check.DEBUGGER, Check.FRIDA),
    response = ResponsePolicy.CALLBACK_ONLY,
    intervalMs = 3000,
    onThreat = { threat -> Log.w("AppCert", threat.detail) },
))

// 온디맨드 1회 스캔
val threats: List<Threat> = AppCert.scan()
```

## 기술 스택

Kotlin(SDK 표면) · C + NDK + CMake(C-only) · 동적 RegisterNatives ·
`ScheduledExecutorService`(주기 탐지, 의존성 0) · demo-app은 Jetpack Compose.
**SDK 런타임 서드파티 의존성 0.** minSdk 24 / compile·target 35 / NDK r26+ /
ABI arm64-v8a·armeabi-v7a·x86_64.

## 구조

```
sdk/        Android 라이브러리(AAR) — Kotlin 표면 + C/NDK 탐지 코어
demo-app/   실시간 탐지 대시보드(Compose)
docs/       설계 명세 · 구현 계획 · 테스트 매트릭스
```

## 문서

- 설계 명세: [docs/superpowers/specs/2026-09-02-appcert-design.md](docs/superpowers/specs/2026-09-02-appcert-design.md)
- 구현 계획: [docs/superpowers/plans/2026-09-02-appcert-core-detection.md](docs/superpowers/plans/2026-09-02-appcert-core-detection.md)

## 한계

탐지-우회는 본질적으로 창과 방패다. AppCert의 목표는 완전 방어가 아니라 **우회 난이도
상승**이다. 강한 방어에는 여러 지표의 조합과 지속적 갱신이 필요하다.

## 참조

OWASP MASVS-RESILIENCE, OWASP MASTG.

## 라이선스

TBD (배포 형태 확정 시 결정).
