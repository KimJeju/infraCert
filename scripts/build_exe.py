"""PyInstaller onedir portable 빌드 (아키텍처 §12, UI 명세 U-10).

사용:  .venv\\Scripts\\python.exe scripts/build_exe.py [--clean]

산출:  dist/InfraGuard/
         InfraGuard.exe
         _internal/            런타임(파이썬·Qt·패키지·파서 프로파일)
         rulepacks/            exe 옆에 복사 — app_root() 가 exe 폴더를 가리키므로 _internal 안이면 안 된다
         (실행 시 생성) workspace/, config.json

원칙:
  - onefile 금지(EDR 오탐·기동 지연·%TEMP% 잔류) → onedir
  - --noconsole. 크래시 로그는 workspace/logs/ 로(app.py 의 excepthook)
  - 온라인 동작 없음. 빌드도 로컬 휠만 쓴다(PyInstaller 는 네트워크를 쓰지 않음)
  - Qt 의 무거운/불필요 모듈은 제외해 반입 심사용 크기를 줄인다
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "InfraGuard"
NAME = "InfraGuard"

# PySide6 에서 쓰지 않는 모듈 — 번들 크기 절감
EXCLUDES = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets", "PySide6.QtWebView",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtQuick3D",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DAnimation", "PySide6.Qt3DExtras",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning", "PySide6.QtLocation",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSerialBus", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtStateMachine", "PySide6.QtTextToSpeech", "PySide6.QtHttpServer",
    "PySide6.QtNetworkAuth", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtSpatialAudio",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools", "PySide6.QtTest",
    "PySide6.QtSql", "PySide6.QtXml", "PySide6.QtSvgWidgets", "PySide6.QtPrintSupport",
    # 앱과 무관한 표준/서드파티
    "tkinter", "unittest", "pydoc", "doctest", "IPython", "jupyter", "matplotlib", "numpy", "PIL",
]

HIDDEN = [
    "infraguard.rules.unix",          # load_all() 안에서 import — 정적 분석 누락 대비
    "infraguard.rules.declarative",
    "winrm", "winrm.protocol", "winrm.transport",   # transport/winrm.py 가 connect() 안에서 lazy import
    "requests_ntlm", "spnego",                       # pywinrm NTLM 인증 경로(조건부 import)
]


def main(argv: list[str]) -> int:
    clean = "--clean" in argv
    if clean:
        shutil.rmtree(ROOT / "build", ignore_errors=True)
        shutil.rmtree(ROOT / "dist", ignore_errors=True)

    sep = ";" if sys.platform == "win32" else ":"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--onedir", "--noconsole", "--name", NAME,
        "--paths", str(ROOT / "src"),
        "--add-data", f"{ROOT / 'src' / 'infraguard' / 'parsing' / 'profiles'}{sep}infraguard/parsing/profiles",
        "--add-data", f"{ROOT / 'src' / 'infraguard' / 'ui' / 'theme'}{sep}infraguard/ui/theme",
        "--collect-submodules", "infraguard",
        "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
    ]
    for m in EXCLUDES:
        cmd += ["--exclude-module", m]
    for h in HIDDEN:
        cmd += ["--hidden-import", h]
    cmd.append(str(ROOT / "src" / "infraguard" / "app.py"))

    # venv 의 base 가 Anaconda 면 _sqlite3/_ssl/_ctypes 등이 base 의 Library\bin DLL 에 의존한다.
    # 그 폴더가 PATH 에 없으면 PyInstaller 의존성 워커가 놓쳐 실행 시 "DLL load failed" 가 난다.
    env = dict(os.environ)
    lib_bin = Path(sys.base_prefix) / "Library" / "bin"
    if lib_bin.exists():
        env["PATH"] = f"{lib_bin}{os.pathsep}{env.get('PATH', '')}"
        print("PATH +=", lib_bin)

    print("PyInstaller:", " ".join(cmd[2:8]), "...")
    r = subprocess.run(cmd, cwd=ROOT, env=env)
    if r.returncode != 0:
        return r.returncode

    # exclude-module 은 파이썬 모듈만 막는다. PySide6 훅이 같이 끌어온 무거운 Qt DLL/플러그인은 직접 걷어낸다.
    trimmed = 0
    qt = DIST / "_internal" / "PySide6"
    for pat in ("*WebEngine*", "*Qml*", "*Quick*", "Qt63D*", "*Charts*", "*DataVisualization*", "*Graphs*",
                "*Multimedia*", "*Pdf*", "*Designer*", "*Bluetooth*", "*Positioning*", "*Location*",
                "*Sensors*", "*SerialPort*", "*SerialBus*", "*RemoteObjects*", "*Scxml*", "*TextToSpeech*",
                "*SpatialAudio*", "*VirtualKeyboard*", "*ShaderTools*", "*Help*", "*Test*", "*Sql*",
                # OpenGL 은 남긴다: opengl32sw.dll 이 GPU 드라이버 없는 고객사 PC 의 소프트웨어 렌더 폴백이다
                "*Xml*", "*PrintSupport*", "*Nfc*", "*NetworkAuth*", "*HttpServer*", "*WebSockets*",
                "*WebChannel*", "*WebView*", "*StateMachine*", "*UiTools*", "*Svg*Widgets*"):
        for p in list(qt.glob(pat)) + list((qt / "plugins").glob(pat)) + list((qt / "qml").glob(pat)):
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
            trimmed += 1
    for d in ("qml", "translations", "plugins/sceneparsers", "plugins/geometryloaders", "plugins/multimedia",
              "plugins/sqldrivers", "plugins/position", "plugins/sensors", "plugins/canbus", "plugins/renderers",
              "plugins/webview", "plugins/tls"):
        # tls 플러그인은 QtNetwork 용 — 앱은 QtNetwork 를 쓰지 않는다(폐쇄망, 아웃바운드 없음)
        shutil.rmtree(qt / d, ignore_errors=True)
    print(f"trimmed {trimmed} Qt artifacts")

    # rulepacks 는 exe 옆(app_root()) 으로. workspace/·config.json 은 실행 시 생성된다.
    dst = DIST / "rulepacks"
    shutil.rmtree(dst, ignore_errors=True)
    # --no-guide: 가이드 파생물(rulepacks/*/guide/, 수동확인 사례 표시용 4MB)을 반입본에서 뺀다
    ignored = ["profiles", "__pycache__"] + (["guide"] if "--no-guide" in argv else [])
    shutil.copytree(ROOT / "rulepacks", dst, ignore=shutil.ignore_patterns(*ignored))
    # 사용자 프로파일은 룰팩 안 profiles/ 에 저장되므로 빈 디렉터리만 마련
    for pack in dst.iterdir():
        if (pack / "manifest.yaml").exists():
            (pack / "profiles").mkdir(exist_ok=True)

    (DIST / "README.txt").write_text(
        "InfraGuard portable\n\n"
        "1. 이 폴더를 통째로 원하는 위치(USB 또는 PC)에 둡니다. 설치·관리자 권한 불필요.\n"
        "2. InfraGuard.exe 실행. workspace/ 와 config.json 이 이 폴더 안에 생깁니다.\n"
        "3. 종료 시 workspace/ 는 완전삭제됩니다(미반출 결과는 먼저 내보내세요).\n"
        "4. 크리덴셜은 디스크에 기록되지 않습니다. 네트워크 접속은 진단 대상 서버 외에 없습니다.\n"
        "5. rulepacks/ 를 교체하면 진단 기준이 바뀝니다(manifest 해시 검증).\n",
        encoding="utf-8",
    )
    total = sum(f.stat().st_size for f in DIST.rglob("*") if f.is_file())
    print(f"\nOK  {DIST}  ({total / 1024 / 1024:.0f} MB, {sum(1 for _ in DIST.rglob('*'))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
