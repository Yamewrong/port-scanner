import os
import re
import tempfile
import subprocess
from pathlib import Path
import json

def check_docker_installed(target_ip, username, pem_file_content):
    pem_path = playbook_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_file_content)
            pem_path = tmp_key.name

        playbook = """
        - hosts: all
          gather_facts: no
          tasks:
            - name: Check Docker installed
              command: docker --version
              register: docker_result
              ignore_errors: yes

            - name: Print result
              debug:
                msg: "{{ docker_result.stdout | default('Docker not found') }}"
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix=".yml") as tmp_playbook:
            tmp_playbook.write(playbook)
            playbook_path = tmp_playbook.name

        cmd = [
            "ansible-playbook", "-i", f"{target_ip},", "-u", username,
            "--private-key", pem_path,
            "--ssh-common-args", "-o StrictHostKeyChecking=no",
            playbook_path
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return "Docker version" in output or "Docker Engine" in output
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Ansible 실행 오류:\n{e.output}")
        return False
    finally:
        if pem_path and os.path.exists(pem_path): os.remove(pem_path)
        if playbook_path and os.path.exists(playbook_path): os.remove(playbook_path)

def get_docker_images(ip, user, pem_content):
    pem_path = playbook_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_content)
            pem_path = tmp_key.name

        playbook = """
        - hosts: all
          gather_facts: no
          become: true
          tasks:
            - name: Get Docker image list
              shell: docker images --format '{{"{{"}}.Repository{{"}}"}}:{{"{{"}}.Tag{{"}}"}}'
              register: docker_images
              ignore_errors: yes

            - name: Output image list
              debug:
                var: docker_images.stdout_lines
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix=".yml") as tmp_playbook:
            tmp_playbook.write(playbook)
            playbook_path = tmp_playbook.name

        cmd = [
            "ansible-playbook", "-i", f"{ip},", "-u", user,
            "--private-key", pem_path,
            "--ssh-common-args", "-o StrictHostKeyChecking=no",
            playbook_path
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        matches = re.findall(r'"docker_images.stdout_lines": \[(.*?)\]', output, re.DOTALL)
        if matches:
            raw_lines = matches[0].split(',')
            return [line.strip().strip('"') for line in raw_lines if line.strip()]
        return []
    except Exception as e:
        print(f"[ERROR] Docker 이미지 가져오기 실패:\n{e}")
        return []
    finally:
        if pem_path and os.path.exists(pem_path): os.remove(pem_path)
        if playbook_path and os.path.exists(playbook_path): os.remove(playbook_path)

def save_and_download_docker_image(ip, user, pem_content, image_name):
    pem_path = playbook_path = None
    local_tar_path = f"./saved_images/{image_name.replace('/', '_').replace(':', '_')}.tar"
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_content)
            pem_path = tmp_key.name

        playbook = f"""
        - hosts: all
          gather_facts: no
          become: true
          tasks:
            - name: Save Docker image as tarball (with sudo)
              become: true
              shell: docker save -o /tmp/image.tar {image_name}
              args:
                warn: false
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.yml') as tmp_playbook:
            tmp_playbook.write(playbook)
            playbook_path = tmp_playbook.name

        cmd = [
            "ansible-playbook", "-i", f"{ip},", "-u", user,
            "--private-key", pem_path,
            "--ssh-common-args", "-o StrictHostKeyChecking=no",
            playbook_path
        ]
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        Path("saved_images").mkdir(exist_ok=True)
        scp_cmd = [
            "scp", "-i", pem_path, "-o", "StrictHostKeyChecking=no",
            f"{user}@{ip}:/tmp/image.tar", local_tar_path
        ]
        subprocess.check_output(scp_cmd, stderr=subprocess.STDOUT, text=True)

        return local_tar_path
    except subprocess.CalledProcessError as e:
        return f"[ERROR] 이미지 저장 또는 다운로드 실패:\n{e.output}"
    finally:
        if pem_path and os.path.exists(pem_path): os.remove(pem_path)
        if playbook_path and os.path.exists(playbook_path): os.remove(playbook_path)

def scan_docker_image_with_trivy(ip, username, pem_content, image_name):
    pem_path = temp_tar_path = json_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_content)
            pem_path = tmp_key.name

        local_filename = image_name.replace("/", "_").replace(":", "_") + ".tar"
        temp_tar_path = os.path.join("/tmp", local_filename)

        save_cmd = f"docker save {image_name} -o /tmp/{local_filename}"
        subprocess.run(["ssh", "-i", pem_path, "-o", "StrictHostKeyChecking=no", f"{username}@{ip}", save_cmd], check=True)
        subprocess.run(f"scp -i {pem_path} -o StrictHostKeyChecking=no {username}@{ip}:/tmp/{local_filename} {temp_tar_path}", shell=True, check=True)
        subprocess.run(f"ssh -i {pem_path} -o StrictHostKeyChecking=no {username}@{ip} 'rm /tmp/{local_filename}'", shell=True)

        safe_name = image_name.replace("/", "_").replace(":", "_")
        report_dir = Path("saved_reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        json_path = report_dir / f"{safe_name}_report.json"

        trivy_cmd = [
            "trivy", "image",
            "--severity", "HIGH,CRITICAL",
            "--scanners", "vuln,secret",      # ← 이것이 핵심!
            "--input", temp_tar_path,
            "--format", "json",
            "--output", str(json_path)
        ]
        subprocess.run(trivy_cmd, check=True)

        return str(json_path)
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Trivy 실행 실패:\n{e.output}"
    except Exception as e:
        return f"[ERROR] 예외 발생: {e}"
    finally:
        if pem_path and os.path.exists(pem_path): os.remove(pem_path)
        if temp_tar_path and os.path.exists(temp_tar_path): os.remove(temp_tar_path)

def parse_trivy_output_from_json(json_file_path):
    if not os.path.exists(json_file_path):
        return []
    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = []
        for target in data.get("Results", []):  # 🔥 이거로 고쳐야 함
            vulns = target.get("Vulnerabilities", [])
            for v in vulns:
                results.append({
                    "Target": target.get("Target"),
                    "VulnerabilityID": v.get("VulnerabilityID"),
                    "PkgName": v.get("PkgName"),
                    "InstalledVersion": v.get("InstalledVersion"),
                    "Severity": v.get("Severity"),
                    "Title": v.get("Title"),
                    "Description": v.get("Description"),
                })
        return results
    except Exception as e:
        print(f"[ERROR] Trivy JSON 파싱 실패: {e}")
        return []


def apply_darkmode_to_trivy_report(report_path):
    dark_style = """
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Pretendard', sans-serif; }
        h1, h2, h3, h4, h5, h6, th { color: #00e6a8; }
        a { color: #80d8ff; }
        table { border-color: #444; }
        table tr:nth-child(even) { background-color: #1e1e1e; }
        table tr:nth-child(odd) { background-color: #181818; }
        table th, table td {
            border: 1px solid #333; padding: 8px;
        }
    </style>
    """
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
    if "<head>" in content:
        content = content.replace("<head>", "<head>" + dark_style, 1)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)
