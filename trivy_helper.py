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
            vulns.append({
                "VulnerabilityID": vuln.get("VulnerabilityID"),
                "PkgName": vuln.get("PkgName"),
                "InstalledVersion": vuln.get("InstalledVersion"),
                "FixedVersion": vuln.get("FixedVersion"),
                "Severity": vuln.get("Severity"),
                "Title": vuln.get("Title"),
                "PrimaryURL": vuln.get("PrimaryURL"),
            })
    return vulns
