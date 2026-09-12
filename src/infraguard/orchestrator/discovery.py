"""사전 Discovery — 자산 하나에 대해 "무엇이 떠 있는가" 를 가볍게 파악하고 진단 프로파일을 추천한다.

nmap 을 동봉하지 않는다(폐쇄망 반입 심사·서브넷 스캔 오해). 대상 호스트 **한 대**에 잘 알려진 포트 몇 개를
TCP connect 로만 두드리고, SSH/HTTP 는 배너만 읽는다. 크리덴셜이 있으면 SSH 로 읽기전용 명령 몇 개(uname·리스닝 포트·
설치 흔적)를 더 본다. 모든 명령은 명령 안전 정책을 통과한 것만.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from infraguard.transport.base import Connection

PORTS: dict[int, str] = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https", 1521: "oracle", 1433: "mssql", 3306: "mysql",
    5432: "postgresql", 5985: "winrm", 5986: "winrm-ssl", 3389: "rdp", 8080: "tomcat/http-alt",
    8443: "https-alt", 7001: "weblogic", 7002: "weblogic-ssl", 8000: "ohs/http", 161: "snmp(udp)",
}
TCP_PORTS = [p for p, n in PORTS.items() if "udp" not in n]
CONNECT_TIMEOUT = 1.5

# SSH 로 볼 때의 읽기전용 명령(정책 통과분)
SSH_PROBES: dict[str, str] = {
    "uname": "uname -srm 2>/dev/null; cat /etc/os-release 2>/dev/null | head -2",
    "listen": "(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || netstat -an 2>/dev/null | grep LISTEN) | head -40",
    "procs": "ps -eo comm= 2>/dev/null | sort -u | grep -xE 'java|httpd|nginx|tomcat|ora_pmon_.*|tnslsnr|mysqld|postgres|sshd|named|smbd|vsftpd|snmpd|sendmail|postfix|master' | head -20",
    "oracle": "ls -d /u01/app/oracle/product/*/* /opt/oracle/product/*/* 2>/dev/null | head -3; command -v sqlplus 2>/dev/null",
    "web": "ls -d /opt/tomcat* /usr/share/tomcat* /opt/apache-tomcat* /u01/app/oracle/middleware* /opt/oracle/middleware* /etc/httpd /etc/apache2 /etc/nginx 2>/dev/null | head -8",
}


@dataclass(slots=True)
class Discovery:
    ports: dict[int, str] = field(default_factory=dict)       # 열린 포트 → 서비스 추정
    banners: dict[int, str] = field(default_factory=dict)     # 포트 → 배너 한 줄
    os: str = ""                                              # uname / os-release
    services: list[str] = field(default_factory=list)        # 발견 서비스 태그: ssh, http, oracle, tomcat, ...
    hints: dict[str, str] = field(default_factory=dict)       # 경로 힌트(ORACLE_HOME 후보, TOMCAT_HOME 후보)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ports": {str(k): v for k, v in self.ports.items()}, "banners": {str(k): v for k, v in self.banners.items()},
                "os": self.os, "services": list(self.services), "hints": dict(self.hints), "notes": list(self.notes)}


def _probe_port(host: str, port: int) -> tuple[int, str] | None:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(1.5)
            banner = ""
            try:
                if port in (80, 8080, 8000, 7001):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = s.recv(256)
                text = data.decode("utf-8", "replace")
                m = re.search(r"(?im)^Server:\s*(.+)$", text)
                banner = (m.group(1) if m else text.splitlines()[0] if text.strip() else "").strip()[:80]
            except OSError:
                pass
            return port, banner
    except OSError:
        return None


def probe_ports(host: str, ports: list[int] | None = None) -> Discovery:
    d = Discovery()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(lambda p: _probe_port(host, p), ports or TCP_PORTS):
            if r:
                port, banner = r
                d.ports[port] = PORTS.get(port, "?")
                if banner:
                    d.banners[port] = banner
    return d


def probe_ssh(conn: Connection, d: Discovery) -> Discovery:
    """연결된 SSH 로 읽기전용 명령 몇 개. 실패해도 조용히 넘어간다(Discovery 는 참고)."""
    for key, cmd in SSH_PROBES.items():
        try:
            r = conn.exec(["sh", "-c", cmd], timeout=20)
        except Exception as e:  # noqa: BLE001
            d.notes.append(f"{key}: {e}")
            continue
        out = (r.stdout or "").strip()
        if key == "uname" and out:
            d.os = out.splitlines()[0]
            m = re.search(r'PRETTY_NAME="?([^"\n]+)', out)
            if m:
                d.os += f" ({m.group(1)})"
        elif key == "listen" and out:
            for m in re.finditer(r":(\d{2,5})(?=\s|$)", out, re.M):
                p = int(m.group(1))
                if p in PORTS and p not in d.ports:
                    d.ports[p] = PORTS[p]
        elif key == "procs" and out:
            for proc in out.splitlines():
                tag = {"httpd": "apache", "nginx": "nginx", "java": "java", "tnslsnr": "oracle", "mysqld": "mysql",
                       "postgres": "postgresql", "named": "dns", "smbd": "smb", "vsftpd": "ftp", "snmpd": "snmp",
                       "sendmail": "mail", "postfix": "mail", "master": "mail"}.get(proc.strip(), "")
                if proc.startswith("ora_pmon_"):
                    tag = "oracle"
                    d.hints["ORACLE_SID"] = proc.split("ora_pmon_", 1)[1]
                if tag and tag not in d.services:
                    d.services.append(tag)
        elif key == "oracle" and out:
            homes = [ln for ln in out.splitlines() if ln.startswith("/")]
            if homes:
                d.hints["ORACLE_HOME"] = homes[0]
                if "oracle" not in d.services:
                    d.services.append("oracle")
        elif key == "web" and out:
            for ln in out.splitlines():
                if "tomcat" in ln and "TOMCAT_HOME" not in d.hints:
                    d.hints["TOMCAT_HOME"] = ln.strip()
                    d.services.append("tomcat") if "tomcat" not in d.services else None
                if "middleware" in ln:
                    d.services.append("weblogic") if "weblogic" not in d.services else None
                if ln.strip() in ("/etc/httpd", "/etc/apache2") and "apache" not in d.services:
                    d.services.append("apache")
    for p, n in d.ports.items():
        tag = {"ssh": "ssh", "http": "http", "https": "http", "oracle": "oracle", "tomcat/http-alt": "tomcat",
               "weblogic": "weblogic", "weblogic-ssl": "weblogic", "ohs/http": "http", "winrm": "winrm",
               "winrm-ssl": "winrm", "rdp": "rdp", "mysql": "mysql", "mssql": "mssql", "telnet": "telnet"}.get(n, "")
        if tag and tag not in d.services:
            d.services.append(tag)
    return d


def recommend_profiles(d: Discovery, platform: str, profile_ids: list[str]) -> list[str]:
    """발견 결과 → 추천 프로파일 id(룰팩에 있는 것만). 순서 = 확신 순."""
    want: list[str] = []
    s = set(d.services)
    if platform in ("windows", "pc") or "winrm" in s or "rdp" in s:
        want.append("windows-native")
    elif platform == "network":
        want += ["cisco-native", "junos-native"]
    else:
        want.append("aix-native" if platform == "unix" else "linux-native")
        if platform == "unix":
            want.append("aix-server")
    if "oracle" in s or 1521 in d.ports:
        want += ["oracle-native", "oracle-db"]
    if s & {"tomcat", "weblogic", "apache", "nginx", "http", "java"} or d.ports.keys() & {80, 443, 8080, 7001, 8000}:
        want.append("web-was")
    return [p for p in want if p in profile_ids]
