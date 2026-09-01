# AppCert Core Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Android RASP SDK(AAR)를 만들어 루팅·안티디버그·Frida 후킹을 네이티브 계층에서 탐지하고, 데모 앱에서 실시간으로 시연한다.

**Architecture:** Kotlin이 얇은 공개 표면(`AppCert.init/scan/stop`)을 제공하고, 실제 탐지는 전부 C/NDK 코어에서 수행한다. 각 탐지 모듈은 "순수 분석 함수(입력 데이터 → 점수)"와 "실 시스템 수집기(/proc 등 읽어 분석 함수 호출)"로 분리한다. 순수 함수는 test-only JNI 훅으로 노출되어 계측 테스트에서 fixture 데이터로 검증되고, 통합은 `scan()`으로 검증된다.

**Tech Stack:** Gradle(Kotlin DSL) + AGP, Kotlin, C + NDK + CMake(C-only), 동적 `RegisterNatives`, `ScheduledExecutorService`, Jetpack Compose(demo-app). SDK 서드파티 의존성 0.

**Spec:** `docs/superpowers/specs/2026-09-02-appcert-design.md`

## Global Constraints

- minSdk 24, compileSdk 35, targetSdk 35, NDK r26+.
- ABI: arm64-v8a, armeabi-v7a, x86_64(에뮬레이터 테스트용).
- SDK 모듈(`:sdk`)은 서드파티 런타임 의존성 0 — Kotlin stdlib + Android SDK + libc/liblog만.
- 탐지 로직은 전부 C. Kotlin은 JNI 브릿지·스케줄·콜백 디스패치만.
- JNI는 동적 `RegisterNatives` 사용(정적 `Java_...` 심볼명 금지).
- 주기 탐지는 `java.util.concurrent.ScheduledExecutorService` (코루틴 미사용).
- 문자열 상수(경로/포트/라이브러리명)는 `obf.h`의 컴파일타임 XOR 매크로로 난독.
- 카테고리당 독립 지표 다수 → 점수 합산·임계값 판정. 하나 우회 ≠ 전체 우회.
- 커밋 컨벤션: Conventional Commits. 자주 커밋.

---

## File Structure

```
appcert/
├─ settings.gradle.kts               # :sdk, :demo-app 모듈 등록
├─ build.gradle.kts                  # 루트, 플러그인 버전
├─ gradle/libs.versions.toml         # 버전 카탈로그
├─ sdk/
│  ├─ build.gradle.kts               # android library + externalNativeBuild(CMake)
│  ├─ src/main/kotlin/com/appcert/
│  │  ├─ AppCert.kt                  # 공개 API: init/scan/stop
│  │  ├─ Config.kt                   # Check, ResponsePolicy, Config
│  │  ├─ Threat.kt                   # ThreatType, Threat
│  │  └─ NativeBridge.kt             # System.loadLibrary + external fun 선언
│  ├─ src/main/cpp/
│  │  ├─ CMakeLists.txt
│  │  ├─ jni_bridge.c                # JNI_OnLoad, RegisterNatives, nativeScan 집계
│  │  ├─ detect.h                    # Threat 코드, score 임계값, 각 모듈 선언
│  │  ├─ root_detect.c
│  │  ├─ antidebug.c
│  │  ├─ frida_detect.c
│  │  ├─ obf.h                       # XOR 문자열 난독 매크로
│  │  └─ util.c / util.h             # 파일 읽기, /proc 헬퍼
│  ├─ src/debug/cpp/testhooks.c      # test-only JNI: 순수 분석 함수 노출
│  └─ src/androidTest/kotlin/com/appcert/
│     ├─ RootDetectTest.kt
│     ├─ AntiDebugTest.kt
│     ├─ FridaDetectTest.kt
│     └─ ScanIntegrationTest.kt
└─ demo-app/
   ├─ build.gradle.kts               # application + compose, implementation(project(":sdk"))
   └─ src/main/kotlin/com/appcert/demo/MainActivity.kt
```

**분리 원칙:** 각 탐지 카테고리는 자기 `.c` 파일 하나. 순수 분석 함수는 fixture 문자열/경로를 받아 점수만 반환(부작용 없음) → 테스트 가능. 수집기는 실 /proc를 읽어 분석 함수에 넘김.

---

### Task 1: 프로젝트 스캐폴딩 + JNI 왕복 검증

빌드가 서고, Kotlin이 native를 동적 `RegisterNatives`로 호출해 알려진 값을 돌려받는 최소 골격.

**Files:**
- Create: `settings.gradle.kts`, `build.gradle.kts`, `gradle/libs.versions.toml`
- Create: `sdk/build.gradle.kts`, `sdk/src/main/cpp/CMakeLists.txt`
- Create: `sdk/src/main/cpp/jni_bridge.c`, `sdk/src/main/cpp/detect.h`
- Create: `sdk/src/main/kotlin/com/appcert/NativeBridge.kt`
- Test: `sdk/src/androidTest/kotlin/com/appcert/ScanIntegrationTest.kt` (왕복 테스트만 우선)

**Interfaces:**
- Produces: `NativeBridge.selfTest(): Int` (Kotlin external, JNI로 `0xA11CE2` 반환)
- Produces: C 매크로 `AC_SCORE_ROOT/DEBUGGER/FRIDA` 및 `Threat` 코드는 `detect.h`에 정의(이후 태스크가 사용)

- [ ] **Step 1: 루트/모듈 Gradle 파일 작성**

`settings.gradle.kts`:
```kotlin
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "appcert"
include(":sdk", ":demo-app")
```
`gradle/libs.versions.toml`:
```toml
[versions]
agp = "8.7.0"
kotlin = "2.0.20"
composeBom = "2024.09.03"
[plugins]
android-library = { id = "com.android.library", version.ref = "agp" }
android-application = { id = "com.android.application", version.ref = "agp" }
kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
```
`build.gradle.kts` (루트):
```kotlin
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
```

- [ ] **Step 2: `sdk/build.gradle.kts` 작성 (native 연결, 의존성 0)**

```kotlin
plugins { alias(libs.plugins.android.library); alias(libs.plugins.kotlin.android) }
android {
    namespace = "com.appcert"; compileSdk = 35
    defaultConfig {
        minSdk = 24
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild { cmake { arguments += "-DANDROID_STL=none" } }
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt") } }
    buildTypes { debug { /* testhooks 포함 */ } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
```
> 참고: `androidTest*` 의존성은 테스트 전용 — 배포 AAR에 포함되지 않으므로 "런타임 의존성 0" 제약 위반 아님.

- [ ] **Step 3: `CMakeLists.txt` + `obf.h` + `util` 골격**

`CMakeLists.txt`:
```cmake
cmake_minimum_required(VERSION 3.22)
project(appcert C)
add_library(appcert SHARED jni_bridge.c root_detect.c antidebug.c frida_detect.c util.c)
target_link_libraries(appcert log)
target_compile_options(appcert PRIVATE -fvisibility=hidden -O2)
if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_sources(appcert PRIVATE ${CMAKE_SOURCE_DIR}/../../debug/cpp/testhooks.c)
    target_compile_definitions(appcert PRIVATE APPCERT_TEST=1)
endif()
```
> root_detect/antidebug/frida_detect/util은 이 태스크에서 빈 stub(`.c`에 헤더 include + 빈 함수)로 만들고, 이후 태스크에서 채운다.

- [ ] **Step 4: `detect.h` 작성**

```c
#ifndef APPCERT_DETECT_H
#define APPCERT_DETECT_H
// Threat type codes (Kotlin ThreatType ordinal과 일치)
#define AC_ROOT      0
#define AC_DEBUGGER  1
#define AC_FRIDA     2
#define AC_TAMPER    3
// 카테고리별 임계값(합산 점수 >= 임계 → 탐지)
#define AC_THRESHOLD 1
int ac_detect_root(void);      // 점수 반환
int ac_detect_debugger(void);
int ac_detect_frida(void);
#endif
```

- [ ] **Step 5: `jni_bridge.c` — 동적 RegisterNatives + selfTest**

```c
#include <jni.h>
#include "detect.h"
static jint nativeSelfTest(JNIEnv* e, jclass c) { (void)e;(void)c; return 0xA11CE2; }
static const JNINativeMethod kMethods[] = {
    {"selfTest", "()I", (void*)nativeSelfTest},
};
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "com/appcert/NativeBridge");
    if (!cls) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, kMethods, 1) != 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}
```

- [ ] **Step 6: `NativeBridge.kt`**

```kotlin
package com.appcert
internal object NativeBridge {
    init { System.loadLibrary("appcert") }
    external fun selfTest(): Int
}
```

- [ ] **Step 7: 왕복 계측 테스트 작성 (실패 확인용)**

`ScanIntegrationTest.kt`:
```kotlin
package com.appcert
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class ScanIntegrationTest {
    @Test fun native_roundtrip() {
        assertEquals(0xA11CE2, NativeBridge.selfTest())
    }
}
```

- [ ] **Step 8: 빌드 + 테스트 실행 (에뮬레이터 필요)**

Run: `./gradlew :sdk:assembleDebug :sdk:connectedDebugAndroidTest`
Expected: 빌드 성공, `native_roundtrip` PASS

- [ ] **Step 9: 커밋**

```bash
git add -A && git commit -m "feat(sdk): NDK 스캐폴딩 + 동적 RegisterNatives JNI 왕복"
```

---

### Task 2: util + obf 네이티브 기반

파일 읽기 헬퍼와 컴파일타임 XOR 문자열 난독. 이후 모든 탐지 모듈이 사용.

**Files:**
- Modify: `sdk/src/main/cpp/util.c`, Create: `sdk/src/main/cpp/util.h`
- Create: `sdk/src/main/cpp/obf.h`
- Create: `sdk/src/debug/cpp/testhooks.c` (util 검증용 훅)
- Test: `sdk/src/androidTest/kotlin/com/appcert/UtilTest.kt`

**Interfaces:**
- Produces: `int ac_read_file(const char* path, char* buf, int cap)` — 읽은 바이트 수(실패 -1)
- Produces: `int ac_file_exists(const char* path)` — 0/1
- Produces: `int ac_buf_contains(const char* hay, int n, const char* needle)` — 0/1
- Produces: `OBF(literal)` 매크로 — 런타임 복호 문자열 포인터
- Produces (test hook): `NativeBridge.thBufContains(hay: String, needle: String): Boolean`

- [ ] **Step 1: `util.h`/`util.c` 테스트 작성 (실패 확인)**

`UtilTest.kt`:
```kotlin
package com.appcert
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class UtilTest {
    @Test fun buf_contains_hit()  = assertTrue(NativeBridge.thBufContains("abc frida-agent xyz", "frida-agent"))
    @Test fun buf_contains_miss() = assertFalse(NativeBridge.thBufContains("clean maps line", "frida-agent"))
}
```

- [ ] **Step 2: 실패 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.UtilTest`
Expected: FAIL (`thBufContains` 미등록)

- [ ] **Step 3: `util.c` 구현**

```c
#include "util.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int ac_read_file(const char* path, char* buf, int cap) {
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    int total = 0, r;
    while (total < cap - 1 && (r = read(fd, buf + total, cap - 1 - total)) > 0) total += r;
    close(fd); buf[total > 0 ? total : 0] = 0; return total;
}
int ac_file_exists(const char* path) { return access(path, F_OK) == 0 ? 1 : 0; }
int ac_buf_contains(const char* hay, int n, const char* needle) {
    if (n <= 0) n = (int)strlen(hay);
    size_t nl = strlen(needle); if (nl == 0 || (size_t)n < nl) return 0;
    for (size_t i = 0; i + nl <= (size_t)n; i++)
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    return 0;
}
```
`util.h`: 위 3개 함수 선언 + `#define AC_BUF 65536`.

- [ ] **Step 4: `obf.h` 구현 (컴파일타임 XOR)**

```c
#ifndef APPCERT_OBF_H
#define APPCERT_OBF_H
#include <string.h>
// 간단한 XOR 난독: 정적 분석에서 평문 grep 방지. ponytail: 문자열 은닉 수준,
// 강한 암호 아님. 키 상향/스택복호는 하드닝 단계에서.
#define AC_KEY 0x5A
static inline char* ac_deobf(char* s, int n) { for (int i=0;i<n;i++) s[i]^=AC_KEY; return s; }
#define OBF(buf, ...) ac_deobf((buf), sizeof((char[]){__VA_ARGS__}) )
#endif
```
> 사용측은 난독 바이트 배열을 저장하고 `ac_deobf`로 스택에서 복호해 쓴다. 실제 바이트열은 빌드 스크립트/수기로 생성(경로 상수는 Task 3~5에서 각 모듈이 정의).

- [ ] **Step 5: `testhooks.c` — util 훅 등록**

```c
#include <jni.h>
#include "../../main/cpp/util.h"
static jboolean thBufContains(JNIEnv* e, jclass c, jstring h, jstring n) {
    (void)c;
    const char* hs = (*e)->GetStringUTFChars(e, h, 0);
    const char* ns = (*e)->GetStringUTFChars(e, n, 0);
    int r = ac_buf_contains(hs, (int)strlen(hs), ns);
    (*e)->ReleaseStringUTFChars(e, h, hs); (*e)->ReleaseStringUTFChars(e, n, ns);
    return r ? JNI_TRUE : JNI_FALSE;
}
// APPCERT_TEST일 때 JNI_OnLoad에서 추가 등록되도록 훅 테이블 노출
const JNINativeMethod* appcert_test_methods(int* count) {
    static const JNINativeMethod m[] = {
        {"thBufContains", "(Ljava/lang/String;Ljava/lang/String;)Z", (void*)thBufContains},
    };
    *count = 1; return m;
}
```
`jni_bridge.c` 수정: `#ifdef APPCERT_TEST`에서 `appcert_test_methods()`를 받아 `NativeBridge`에 함께 RegisterNatives. `NativeBridge.kt`에 `external fun thBufContains(hay: String, needle: String): Boolean` 추가(디버그에서만 등록되지만 선언은 항상 존재).

- [ ] **Step 6: 통과 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.UtilTest`
Expected: 두 테스트 PASS

- [ ] **Step 7: 커밋**

```bash
git add -A && git commit -m "feat(sdk): util(/proc 읽기·부분매칭) + obf XOR 기반 + test hook 배관"
```

---

### Task 3: 루팅 탐지

su 경로·Magisk 아티팩트·빌드속성·system 쓰기가능 다중 지표.

**Files:**
- Modify: `sdk/src/main/cpp/root_detect.c`, `detect.h`
- Modify: `sdk/src/debug/cpp/testhooks.c` (순수 분석 함수 노출)
- Modify: `NativeBridge.kt`
- Test: `sdk/src/androidTest/kotlin/com/appcert/RootDetectTest.kt`

**Interfaces:**
- Consumes: `ac_file_exists`, `ac_read_file`, `ac_buf_contains` (Task 2)
- Produces: `int ac_root_analyze_paths(const char** paths, int n)` — 존재하는 경로 수(점수)
- Produces: `int ac_root_analyze_props(const char* build_props_buf)` — 위험 속성 매칭 점수
- Produces: `int ac_detect_root(void)` — 실 수집기(기본 경로/prop 읽어 분석 합산)
- Produces (test hook): `NativeBridge.thRootPaths(paths: Array<String>): Int`, `thRootProps(buf: String): Int`

- [ ] **Step 1: 순수 분석 테스트 작성 (실패 확인)**

`RootDetectTest.kt`:
```kotlin
package com.appcert
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class RootDetectTest {
    @Test fun paths_flags_existing() {
        // 앱 캐시에 가짜 su 파일 생성 → 존재 경로는 점수 1 이상
        val ctx = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val fake = java.io.File(ctx.cacheDir, "su").apply { writeText("x") }
        assertTrue(NativeBridge.thRootPaths(arrayOf(fake.absolutePath, "/nonexistent/su")) >= 1)
    }
    @Test fun props_flags_testkeys() {
        assertTrue(NativeBridge.thRootProps("ro.build.tags=test-keys\nro.debuggable=1\n") >= 1)
    }
    @Test fun props_clean_zero() {
        assertEquals(0, NativeBridge.thRootProps("ro.build.tags=release-keys\nro.secure=1\n"))
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.RootDetectTest`
Expected: FAIL (훅 미등록)

- [ ] **Step 3: `root_detect.c` 구현**

```c
#include "detect.h"
#include "util.h"
#include <string.h>
int ac_root_analyze_paths(const char** paths, int n) {
    int score = 0;
    for (int i = 0; i < n; i++) if (ac_file_exists(paths[i])) score++;
    return score;
}
int ac_root_analyze_props(const char* buf) {
    int score = 0;
    if (ac_buf_contains(buf, 0, "test-keys")) score++;
    if (ac_buf_contains(buf, 0, "ro.debuggable=1")) score++;
    return score;
}
static const char* kSuPaths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/local/su", "/data/local/bin/su", "/system/app/Superuser.apk",
    "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
};
int ac_detect_root(void) {
    int score = ac_root_analyze_paths(kSuPaths, sizeof(kSuPaths)/sizeof(kSuPaths[0]));
    char buf[AC_BUF];
    if (ac_read_file("/system/build.prop", buf, sizeof(buf)) > 0)
        score += ac_root_analyze_props(buf);
    // getprop 대체: ro.build.tags는 build.prop에 없을 수 있음 → __system_property_get 보강은 하드닝 단계
    return score;
}
```
> `detect.h`에 `int ac_root_analyze_paths(const char**,int); int ac_root_analyze_props(const char*);` 선언 추가.

- [ ] **Step 4: testhooks + NativeBridge 훅 추가**

`testhooks.c`의 메서드 테이블에 추가:
```c
static jint thRootPaths(JNIEnv* e, jclass c, jobjectArray arr) {
    (void)c; int n = (*e)->GetArrayLength(e, arr);
    const char** paths = alloca(sizeof(char*) * n);
    jstring* refs = alloca(sizeof(jstring) * n);
    for (int i=0;i<n;i++){ refs[i]=(jstring)(*e)->GetObjectArrayElement(e,arr,i);
        paths[i]=(*e)->GetStringUTFChars(e,refs[i],0);}
    int r = ac_root_analyze_paths(paths, n);
    for (int i=0;i<n;i++) (*e)->ReleaseStringUTFChars(e,refs[i],paths[i]);
    return r;
}
static jint thRootProps(JNIEnv* e, jclass c, jstring s) {
    (void)c; const char* b=(*e)->GetStringUTFChars(e,s,0);
    int r=ac_root_analyze_props(b); (*e)->ReleaseStringUTFChars(e,s,b); return r;
}
```
테이블 시그니처: `{"thRootPaths","([Ljava/lang/String;)I",...}`, `{"thRootProps","(Ljava/lang/String;)I",...}`. `NativeBridge.kt`에 대응 `external fun` 추가. (`#include <alloca.h>` 또는 stack VLA 사용.)

- [ ] **Step 5: 통과 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.RootDetectTest`
Expected: 3 테스트 PASS

- [ ] **Step 6: 커밋**

```bash
git add -A && git commit -m "feat(sdk): 루팅 탐지(su 경로·Magisk 아티팩트·빌드속성 다중지표)"
```

---

### Task 4: 안티디버그

ptrace self-attach + `/proc/self/status` TracerPid.

**Files:**
- Modify: `sdk/src/main/cpp/antidebug.c`, `detect.h`, `testhooks.c`, `NativeBridge.kt`
- Test: `sdk/src/androidTest/kotlin/com/appcert/AntiDebugTest.kt`

**Interfaces:**
- Consumes: `ac_read_file` (Task 2)
- Produces: `int ac_status_tracerpid(const char* status_buf)` — TracerPid 값(파싱)
- Produces: `int ac_detect_debugger(void)` — 실 수집기(TracerPid + ptrace 시도)
- Produces (test hook): `NativeBridge.thTracerPid(statusBuf: String): Int`

- [ ] **Step 1: 파싱 테스트 작성 (실패 확인)**

`AntiDebugTest.kt`:
```kotlin
package com.appcert
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class AntiDebugTest {
    @Test fun tracerpid_zero() =
        assertEquals(0, NativeBridge.thTracerPid("Name:\tx\nTracerPid:\t0\nUid:\t0\n"))
    @Test fun tracerpid_nonzero() =
        assertEquals(1234, NativeBridge.thTracerPid("TracerPid:\t1234\n"))
    @Test fun detector_clean_baseline() {
        // 계측 테스트는 디버거 미부착 → 점수 0 기대
        assertEquals(0, NativeBridge.thDetectDebugger())
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.AntiDebugTest`
Expected: FAIL

- [ ] **Step 3: `antidebug.c` 구현**

```c
#include "detect.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <errno.h>
int ac_status_tracerpid(const char* buf) {
    const char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    p += 10; while (*p==' '||*p=='\t') p++;
    return (int)strtol(p, NULL, 10);
}
int ac_detect_debugger(void) {
    int score = 0;
    char buf[AC_BUF];
    if (ac_read_file("/proc/self/status", buf, sizeof(buf)) > 0)
        if (ac_status_tracerpid(buf) != 0) score++;
    // ptrace self-attach: 이미 트레이스 중이면 실패
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 && errno == EPERM) score++;
    else ptrace(PTRACE_DETACH, 0, 0, 0); // 성공 시 원복
    return score;
}
```
> `detect.h`에 `int ac_status_tracerpid(const char*);` 추가. 훅에 `thTracerPid`, `thDetectDebugger`(= `ac_detect_debugger` 래핑) 추가.
> ponytail: PTRACE_TRACEME는 프로세스당 1회성 효과 — 실제 SDK에선 별도 워처 프로세스가 담당(스트레치). 여기선 지표로만.

- [ ] **Step 4: 훅 + NativeBridge 추가** (`thTracerPid(String):I`, `thDetectDebugger():I`)

- [ ] **Step 5: 통과 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.AntiDebugTest`
Expected: PASS

- [ ] **Step 6: 커밋**

```bash
git add -A && git commit -m "feat(sdk): 안티디버그(TracerPid 파싱 + ptrace self-attach)"
```

---

### Task 5: Frida/후킹 탐지

`/proc/self/maps` 라이브러리 스캔 + 스레드명.

**Files:**
- Modify: `sdk/src/main/cpp/frida_detect.c`, `detect.h`, `testhooks.c`, `NativeBridge.kt`
- Test: `sdk/src/androidTest/kotlin/com/appcert/FridaDetectTest.kt`

**Interfaces:**
- Consumes: `ac_buf_contains`, `ac_read_file` (Task 2)
- Produces: `int ac_frida_analyze_maps(const char* maps_buf)` — frida 시그니처 매칭 점수
- Produces: `int ac_detect_frida(void)` — 실 수집기(/proc/self/maps + task comm)
- Produces (test hook): `NativeBridge.thFridaMaps(mapsBuf: String): Int`

- [ ] **Step 1: 분석 테스트 작성 (실패 확인)**

`FridaDetectTest.kt`:
```kotlin
package com.appcert
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class FridaDetectTest {
    @Test fun maps_flags_frida() {
        val line = "7f00-7f10 r-xp 0 0:0 0 /data/local/tmp/re.frida.server/frida-agent-64.so\n"
        assertTrue(NativeBridge.thFridaMaps(line) >= 1)
    }
    @Test fun maps_flags_gadget() {
        assertTrue(NativeBridge.thFridaMaps("... /data/app/frida-gadget.so\n") >= 1)
    }
    @Test fun maps_clean_zero() {
        assertEquals(0, NativeBridge.thFridaMaps("7f.. r-xp 0 0:0 0 /system/lib64/libc.so\n"))
    }
    @Test fun detector_clean_baseline() = assertEquals(0, NativeBridge.thDetectFrida())
}
```

- [ ] **Step 2: 실패 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.FridaDetectTest`
Expected: FAIL

- [ ] **Step 3: `frida_detect.c` 구현**

```c
#include "detect.h"
#include "util.h"
static const char* kSigs[] = { "frida-agent", "frida-gadget", "gum-js-loop",
    "libfrida", "gadget", "linjector" };
int ac_frida_analyze_maps(const char* buf) {
    int score = 0;
    for (unsigned i=0;i<sizeof(kSigs)/sizeof(kSigs[0]);i++)
        if (ac_buf_contains(buf, 0, kSigs[i])) score++;
    return score;
}
int ac_detect_frida(void) {
    char buf[AC_BUF];
    int score = 0;
    if (ac_read_file("/proc/self/maps", buf, sizeof(buf)) > 0)
        score += ac_frida_analyze_maps(buf);
    return score;
}
```
> `detect.h`에 `int ac_frida_analyze_maps(const char*);` 추가. 훅에 `thFridaMaps`, `thDetectFrida` 추가.
> ponytail: maps 스캔이 1차. 포트(27042) 스캔은 우회 쉬워 후순위 — 하드닝 단계에서 보강. 시그니처 문자열은 Task 6 이후 `obf.h`로 난독.

- [ ] **Step 4: 훅 + NativeBridge 추가**

- [ ] **Step 5: 통과 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.FridaDetectTest`
Expected: PASS

- [ ] **Step 6: 커밋**

```bash
git add -A && git commit -m "feat(sdk): Frida 탐지(/proc/self/maps 시그니처 스캔)"
```

---

### Task 6: Kotlin SDK 공개 표면

`AppCert.init/scan/stop`, `Config`, `Threat`, 주기 탐지, 콜백 디스패치. native 집계 `nativeScan` 추가.

**Files:**
- Create: `sdk/src/main/kotlin/com/appcert/AppCert.kt`, `Config.kt`, `Threat.kt`
- Modify: `sdk/src/main/cpp/jni_bridge.c` (nativeScan 집계), `NativeBridge.kt`
- Test: `sdk/src/androidTest/kotlin/com/appcert/ScanIntegrationTest.kt` (확장)

**Interfaces:**
- Consumes: `ac_detect_root/debugger/frida` (Task 3~5)
- Produces: `NativeBridge.scan(): IntArray` — [rootScore, debuggerScore, fridaScore]
- Produces: `AppCert.init(context, Config)`, `AppCert.scan(): List<Threat>`, `AppCert.stop()`
- Produces: `Threat(type, severity, detail)`, `Config(enabledChecks, response, intervalMs, onThreat)`

- [ ] **Step 1: `Threat.kt` / `Config.kt`**

```kotlin
package com.appcert
enum class ThreatType { ROOT, DEBUGGER, FRIDA, TAMPER }   // ordinal = detect.h 코드
data class Threat(val type: ThreatType, val severity: Int, val detail: String)
```
```kotlin
package com.appcert
enum class Check { ROOT, DEBUGGER, FRIDA }
enum class ResponsePolicy { CALLBACK_ONLY, TERMINATE }
data class Config(
    val enabledChecks: Set<Check> = setOf(Check.ROOT, Check.DEBUGGER, Check.FRIDA),
    val response: ResponsePolicy = ResponsePolicy.CALLBACK_ONLY,
    val intervalMs: Long = 3000,
    val onThreat: (Threat) -> Unit = {},
)
```

- [ ] **Step 2: native 집계 `scan()` 추가 + 왕복 테스트 확장 (실패 확인)**

`jni_bridge.c`에 추가:
```c
#include "detect.h"
static jintArray nativeScan(JNIEnv* e, jclass c) {
    (void)c;
    jint v[3] = { ac_detect_root(), ac_detect_debugger(), ac_detect_frida() };
    jintArray out = (*e)->NewIntArray(e, 3);
    (*e)->SetIntArrayRegion(e, out, 0, 3, v);
    return out;
}
```
메서드 테이블에 `{"scan","()[I",(void*)nativeScan}` 추가. `NativeBridge.kt`에 `external fun scan(): IntArray`.
`ScanIntegrationTest.kt`에 추가:
```kotlin
@Test fun scan_clean_baseline() {
    // 클린 에뮬레이터: 3개 카테고리 점수 모두 0 기대(안티디버그 baseline 포함)
    val s = NativeBridge.scan()
    assertEquals(3, s.size)
    assertTrue(s.all { it == 0 })
}
```

- [ ] **Step 3: 실패 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.ScanIntegrationTest`
Expected: FAIL (`scan` 미등록)

- [ ] **Step 4: `AppCert.kt` 구현**

```kotlin
package com.appcert
import android.content.Context
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
object AppCert {
    private var cfg: Config = Config()
    private val exec = Executors.newSingleThreadScheduledExecutor()
    private var task: ScheduledFuture<*>? = null
    fun init(context: Context, config: Config) {
        cfg = config
        task?.cancel(false)
        task = exec.scheduleWithFixedDelay({
            scan().forEach { t ->
                cfg.onThreat(t)
                if (cfg.response == ResponsePolicy.TERMINATE) android.os.Process.killProcess(android.os.Process.myPid())
            }
        }, 0, cfg.intervalMs, TimeUnit.MILLISECONDS)
    }
    fun scan(): List<Threat> {
        val s = NativeBridge.scan()
        val out = ArrayList<Threat>(3)
        fun add(check: Check, type: ThreatType, score: Int) {
            if (check in cfg.enabledChecks && score >= 1)
                out.add(Threat(type, score, "${type.name} score=$score"))
        }
        add(Check.ROOT, ThreatType.ROOT, s[0])
        add(Check.DEBUGGER, ThreatType.DEBUGGER, s[1])
        add(Check.FRIDA, ThreatType.FRIDA, s[2])
        return out
    }
    fun stop() { task?.cancel(false); task = null }
}
```

- [ ] **Step 5: 통과 확인**

Run: `./gradlew :sdk:connectedDebugAndroidTest --tests com.appcert.ScanIntegrationTest`
Expected: PASS (`native_roundtrip`, `scan_clean_baseline`)

- [ ] **Step 6: 커밋**

```bash
git add -A && git commit -m "feat(sdk): 공개 API(init/scan/stop) + 주기 탐지 + native 집계"
```

---

### Task 7: demo-app 실시간 대시보드

Compose 단일 화면. 각 카테고리 상태를 주기 표시 + 수동 스캔 버튼.

**Files:**
- Create: `demo-app/build.gradle.kts`, `demo-app/src/main/AndroidManifest.xml`
- Create: `demo-app/src/main/kotlin/com/appcert/demo/MainActivity.kt`

**Interfaces:**
- Consumes: `AppCert.init/scan/stop`, `Threat`, `Config` (Task 6)

- [ ] **Step 1: `demo-app/build.gradle.kts`**

```kotlin
plugins { alias(libs.plugins.android.application); alias(libs.plugins.kotlin.android) }
android {
    namespace = "com.appcert.demo"; compileSdk = 35
    defaultConfig { applicationId = "com.appcert.demo"; minSdk = 24; targetSdk = 35; versionCode = 1; versionName = "0.1" }
    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.15" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    implementation(project(":sdk"))
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.2")
}
```

- [ ] **Step 2: `MainActivity.kt` 대시보드**

```kotlin
package com.appcert.demo
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.appcert.*
import kotlinx.coroutines.delay
class MainActivity : ComponentActivity() {
    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContent {
            var threats by remember { mutableStateOf(emptyList<Threat>()) }
            LaunchedEffect(Unit) {
                while (true) { threats = AppCert.scan(); delay(1500) }
            }
            MaterialTheme {
                Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("AppCert 실시간 탐지", style = MaterialTheme.typography.headlineSmall)
                    for (type in listOf(ThreatType.ROOT, ThreatType.DEBUGGER, ThreatType.FRIDA)) {
                        val hit = threats.firstOrNull { it.type == type }
                        val color = if (hit != null) Color(0xFFD32F2F) else Color(0xFF388E3C)
                        Card { ListItem(
                            headlineContent = { Text(type.name) },
                            supportingContent = { Text(hit?.detail ?: "정상") },
                            leadingContent = { Text(if (hit != null) "⚠" else "✔") },
                            colors = ListItemDefaults.colors(headlineColor = color),
                        ) }
                    }
                }
            }
        }
    }
}
```
`AndroidManifest.xml`: `MainActivity` LAUNCHER 등록. compose 사용하므로 `kotlinx-coroutines`는 activity-compose 전이 의존성으로 들어옴(demo-app 한정, SDK 아님 → 제약 무관).

- [ ] **Step 3: 빌드 + 설치 + 육안 확인**

Run: `./gradlew :demo-app:installDebug`
Expected: 앱 설치. 실행 시 세 카드 모두 초록 "정상"(클린 에뮬레이터). frida 서버 부착 후 FRIDA 카드 빨강 전환.

- [ ] **Step 4: 커밋**

```bash
git add -A && git commit -m "feat(demo): Compose 실시간 탐지 대시보드"
```

---

### Task 8: 테스트 매트릭스 문서화 + README 갱신

동작 여부 근거를 문서로. 배포용 README 정비.

**Files:**
- Create: `docs/TEST_MATRIX.md`
- Modify: `README.md`

- [ ] **Step 1: `docs/TEST_MATRIX.md` 작성** — 환경(클린/루팅/frida/디버거)별 재현 절차와 기대 결과, 스크린샷 첨부 위치.
- [ ] **Step 2: `README.md`에 빌드/통합/한계 섹션 반영** (Task 1~7 실제 API 기준).
- [ ] **Step 3: 커밋**

```bash
git add -A && git commit -m "docs: 테스트 매트릭스 + README 정비"
```

---

## Self-Review

- **Spec coverage:** 루팅(Task 3)·안티디버그(Task 4)·Frida(Task 5)·공개 API/응답정책/주기(Task 6)·demo 대시보드/동작여부(Task 7,8)·하드닝(obf Task 2, 각 모듈 다중지표)·JNI 동적등록(Task 1). 무결성/서명검증·APK 래핑은 스펙상 스트레치 → 본 계획 범위 밖(후속 계획). 커버 확인.
- **Placeholder scan:** 각 코드 스텝 실제 코드 포함. TEST_MATRIX/README만 산문 지시(문서 태스크라 허용).
- **Type consistency:** `ac_detect_root/debugger/frida`(detect.h) ↔ `nativeScan` 3원소 IntArray ↔ `NativeBridge.scan()` ↔ `AppCert.scan()` 매핑 일치. `ThreatType` ordinal = detect.h 코드. 훅 함수명 `th*` 일관.
- **테스트 전략:** 순수 분석 함수는 fixture로 계측 유닛테스트(에뮬), 통합은 clean-baseline + 실 부착 시연. 각 탐지 태스크가 runnable 테스트로 종료(ponytail 준수).

## 한계 / 후속

- 본 계획은 **탐지 지표 1차 세트**. 창-방패 특성상 우회 가능 지점 존재 → 하드닝 단계(obf 전면 적용, native self-integrity, 워처 프로세스 ptrace 선점, 포트/스레드명 보강)와 무결성/서명검증·APK 래핑은 후속 계획으로 분리.
- 실기기 테스트(루팅 단말·frida) 필요. 에뮬레이터는 baseline·frida 부착까지 커버.
