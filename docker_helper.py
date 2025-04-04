import subprocess
import re

def get_docker_port_image_map():
    cmd = ['docker', 'ps', '--format', '{{.Image}} {{.Ports}}']
    result = subprocess.check_output(cmd).decode().strip().split('\n')

    port_image_map = {}

    for line in result:
        parts = line.split(' ', 1)
        if len(parts) < 2:
            continue
        image_name, ports_info = parts
        matches = re.findall(r':(\d+)->', ports_info)  # 포트만 추출
        for port in matches:
            port_image_map[int(port)] = image_name  # 포트 기준 매핑

    return port_image_map

