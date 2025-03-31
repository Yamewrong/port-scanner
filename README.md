<h1 align="center">🔍 Advanced Port & Service Scanner</h1>
<p align="center">
  <b>보안 전문가 수준의 자산 점검 도구</b><br>
  <i>포트 스캔부터 민감 자산 인증 우회 탐지, CVE 취약점 경고까지 한 번에!</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python">
  <img src="https://img.shields.io/badge/Flask-2.x-lightgrey?logo=flask">
  <img src="https://img.shields.io/badge/Selenium-Automation-orange?logo=selenium">
  <img src="https://img.shields.io/badge/Docker-Redis--MongoDB-critical?logo=docker">
</p>

---

## 🛡️ 주요 기능

| 기능 | 설명 |
|------|------|
| ✅ 포트 스캔 | 병렬로 빠르게 TCP 포트 스캔 (1–1024) |
| ✅ 위험 포트 탐지 | SMB, RDP, FTP 등 고위험 포트 자동 식별 |
| ✅ 조합 기반 위험 탐지 | HTTP+HTTPS, FTP+SMB 등 이상 조합 경고 |
| ✅ CVE 연계 | Shodan API + EPSS API 기반 고위험 취약점 경고 |
| ✅ 웹 서비스 스크린샷 | Selenium으로 실시간 웹 페이지 캡처 |
| ✅ 민감 자산 탐지 | Redis, MongoDB, Elasticsearch 외부 노출 경고 |
| ✅ 인증 우회 감지 | Redis 등 인증 없이 접속 가능한 자산 실시간 탐지 |

---

## 🖥️ 실행 화면

| 📊 전체 리포트 | 🌐 웹 서비스 스크린샷 |
|----------------|------------------------|
| ![report](./screenshots/report1.png) | ![webshot](./screenshots/web1.png) |

> 🔐 리포트 예시: "Redis 인증 없이 접속 가능합니다. 즉시 차단 필요"

---

## ⚙️ 사용 기술

- `Python 3.10`
- `Flask` - 웹 UI
- `Selenium` - 웹 서비스 캡처
- `requests`, `socket`, `ThreadPoolExecutor`
- `Docker` (Redis/Mongo 테스트용)

---

