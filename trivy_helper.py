import subprocess
import os
import json


def scan_with_trivy(image_name):
    output_file = f"trivy_{image_name.replace(':', '_')}.json"
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

