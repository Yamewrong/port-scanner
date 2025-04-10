import subprocess
import os
import json
from app.utils.docker_helper import get_docker_port_image_map
REPORT_DIR = "trivy_reports"

def scan_with_trivy(image_name):
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe_name = image_name.replace(":", "_").replace("/", "_")
    output_file = os.path.join(REPORT_DIR, f"{safe_name}.json")

    subprocess.run([
        "trivy", "image", image_name,
        "--format", "json", "-o", output_file
    ], check=True)

    if not os.path.exists(output_file):
        return []

    with open(output_file, encoding='utf-8') as f:
        data = json.load(f)


    vulns = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            pkg = vuln.get("PkgName")
            installed = vuln.get("InstalledVersion")
            fixed = vuln.get("FixedVersion")
            guideline = None

            if pkg and installed and fixed:
                guideline = (
                    f"이 취약점은 `{pkg}` 패키지의 구버전({installed})에서 발생합니다.\n"
                    f"💡 해결 방법: `{pkg}`를 최신 버전({fixed} 이상)으로 업데이트하세요.\n\n"
                    f"🛠 리눅스에서는 아래 명령어로 간단히 업데이트할 수 있습니다:\n"
                    f"$ sudo apt update && sudo apt install {pkg}"
                )

            vulns.append({
                "VulnerabilityID": vuln.get("VulnerabilityID"),
                "PkgName": pkg,
                "InstalledVersion": installed,
                "FixedVersion": fixed,
                "Severity": vuln.get("Severity"),
                "Title": vuln.get("Title"),
                "PrimaryURL": vuln.get("PrimaryURL"),
                "Guideline": guideline
            })
    return vulns
    print(f"[Trivy] {image_name} 분석 완료 → 취약점 {len(vulns)}개 발견")

def enrich_with_trivy(ip, results, is_docker=True):
    if not is_docker:
        return

    docker_map = get_docker_port_image_map() if is_docker else {}

    for r in results:
        port = r['port']
        if port in docker_map:
            image_name, service_name = docker_map[port]
            r['docker_image'] = image_name
            r['service_name'] = service_name or infer_service_from_image(image_name)

            try:
                safe_name = image_name.replace('/', '_').replace(':', '_')
                output_file = f"trivy_reports/{safe_name}.json"

                if not os.path.exists(output_file):
                    r['trivy_vulns'] = scan_with_trivy(image_name)
                else:
                    with open(output_file, encoding='utf-8') as f:
                        existing = json.load(f)

                    # 👇 이 부분 중요
                    r['trivy_vulns'] = [
                        vuln
                        for result in existing.get("Results", [])
                        for vuln in result.get("Vulnerabilities", [])
                    ]
            except Exception as e:
                r['trivy_vulns'] = []
        else:
            r['trivy_vulns'] = []