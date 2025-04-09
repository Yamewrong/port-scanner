import os
import tempfile
import subprocess

def check_docker_installed(target_ip, username, pem_file_content):
    """Ansible을 이용해 원격 서버에서 Docker 설치 여부 확인"""
    pem_path = None
    playbook_path = None

    try:
        # 1️⃣ PEM 키를 임시 파일로 저장
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_file_content)
            pem_path = tmp_key.name

        # 2️⃣ 인벤토리 생성
        inventory = f"{target_ip} ansible_user={username} ansible_ssh_private_key_file={pem_path} ansible_ssh_common_args='-o StrictHostKeyChecking=no'"

        # 3️⃣ Ansible 플레이북 생성
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

        # 4️⃣ Ansible 실행
        cmd = ["ansible-playbook", "-i", inventory, playbook_path]
        print("[DEBUG] 실행 명령:", " ".join(cmd))
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        # 5️⃣ 결과 파싱
        print("[DEBUG] Ansible Output:\n", output)
        return "Docker version" in output or "Docker Engine" in output

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Ansible 실행 오류:\n{e.output}")
        return False

    finally:
        # 6️⃣ 임시 파일 삭제
        if pem_path and os.path.exists(pem_path):
            os.remove(pem_path)
        if playbook_path and os.path.exists(playbook_path):
            os.remove(playbook_path)
def scan_docker_image_with_trivy(ip, username, pem_content, image_name):
    """원격 서버에서 docker pull + trivy 검사 실행 후 결과 리턴"""
    import tempfile, subprocess, os
    pem_path = None
    playbook_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as tmp_key:
            tmp_key.write(pem_content)
            pem_path = tmp_key.name

        inventory = f"{ip} ansible_user={username} ansible_ssh_private_key_file={pem_path} ansible_ssh_common_args='-o StrictHostKeyChecking=no'"

        playbook = f"""
        - hosts: all
          gather_facts: no
          tasks:
            - name: Pull Docker image
              command: docker pull {image_name}

            - name: Run Trivy scan
              command: trivy image --severity HIGH,CRITICAL {image_name}
              register: trivy_result
              ignore_errors: yes

            - name: Print result
              debug:
                msg: "{{{{ trivy_result.stdout | default('No output') }}}}"
        """

        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix=".yml") as tmp_playbook:
            tmp_playbook.write(playbook)
            playbook_path = tmp_playbook.name

        cmd = ["ansible-playbook", "-i", inventory, playbook_path]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        return output

    except subprocess.CalledProcessError as e:
        return f"[ERROR] Ansible 오류 발생:\n{e.output}"

    finally:
        if pem_path and os.path.exists(pem_path):
            os.remove(pem_path)
        if playbook_path and os.path.exists(playbook_path):
            os.remove(playbook_path)
def parse_trivy_output(output):
    """
    Trivy 명령 결과에서 CVE, 심각도, 패키지명, 버전, 설명을 추출하는 함수.
    """
    import re
    findings = []
    pattern = re.compile(r'^(CVE-\d{4}-\d+)\s*\|\s*(\w+)\s*\|\s*([\w\-.@/]+)\s*\|\s*([\w\-.@]+)\s*\|\s*(.+)$')

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            cve_id, severity, pkg, version, desc = match.groups()
            findings.append({
                'cve_id': cve_id,
                'severity': severity,
                'package': pkg,
                'version': version,
                'description': desc
            })

    return findings

