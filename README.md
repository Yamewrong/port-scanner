# 🔍 PortScanner: 포트 기반 보안 진단 자동화 도구

![Badge](https://img.shields.io/badge/Python-3.10-blue?style=flat-square)
![Badge](https://img.shields.io/badge/Flask-2.2-lightgrey?style=flat-square)
![Badge](https://img.shields.io/badge/Docker-Integration-green?style=flat-square)
![Badge](https://img.shields.io/badge/Trivy-VulnScan-orange?style=flat-square)
![Badge](https://img.shields.io/badge/nuclei-CVE--Analysis-critical?style=flat-square)

> 🛡️ **보안 전문가를 위한 자동화된 포트 기반 서비스 식별 & 취약점 분석 시스템**  
> Docker 기반 서비스 식별, 취약점(CVE) 분석, EPSS 위험도 분류, 웹 서비스 식별, 리포트 자동화까지 한 번에!

---

## 📦 기능 요약

### ✅ 서비스 식별 자동화
- 🔎 `docker ps` + `docker inspect` → 포트별 Docker 이미지, 서비스 자동 매핑
- 🧠 이미지명, Entrypoint, Cmd, Label 기반 **서비스명 추론 알고리즘 내장**

### ✅ 취약점 진단
- 🧪 [Trivy](https://github.com/aquasecurity/trivy) 기반 Docker 이미지 취약점 스캔
- 🧨 [nuclei](https://github.com/projectdiscovery/nuclei) 기반 CVE 탐지 및 EPSS 위험도 분석
- 📊 고위험(≥ 0.7), 중간(≥ 0.4), 저위험(< 0.4) 자동 분류 및 대응 가이드 생성

### ✅ 포트 스캐닝 & 선택적 진단
- 🌐 `전체 포트(1~1024)` 또는 `선택 프로토콜 기반` 스캔 지원
- 🧩 FTP, SSH, HTTP, DNS, Redis, MongoDB, Jenkins, Elasticsearch 등 30+ 프로토콜 지원
- ⚡ 추후 Half-Open(반개방형) 스캔 모드 지원 예정

### ✅ 웹 서비스 정보 수집
- 🖼️ 웹 페이지 **타이틀 / 서버 / 스크린샷** 자동 수집
- 📷 `selenium` 기반 캡처 기능 포함

### ✅ UI 및 리포트
- 🖥️ `Flask` 웹 대시보드 기반 직관적 결과 확인
- 📄 취약점 수, 서비스 매핑, Docker 이미지별 상세 분석 제공
- 📥 TXT 다운로드 및 CVE 상세 페이지 연동

---

## 🛠️ 설치 및 실행

```bash
git clone https://github.com/yourname/port-scanner.git
cd port-scanner

# Python 패키지 설치
pip install -r requirements.txt

# 실행
python app.py
```

🌐 주요 기술 스택
Python 3.10

Flask

Docker

Trivy

nuclei + EPSS API

Selenium

BeautifulSoup

📁 폴더 구조

port-scanner/  
├── app.py                      # 메인 플라스크 서버   
├── docker_helper.py           # Docker 이미지 → 서비스 추론 로직  
├── trivy_helper.py            # Trivy 취약점 검사 모듈  
├── scanners/                  # 프로토콜별 스캐너 모음  
├── templates/                 # HTML 결과 템플릿  
├── static/captures/           # 웹 서비스 스크린샷 저장  
├── trivy_reports/             # Trivy 분석 JSON 리포트 저장  
└── README.md
 
