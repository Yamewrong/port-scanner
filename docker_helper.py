import subprocess
import re
def get_docker_port_image_map():
    docker_ports = {}
    try:
        output = subprocess.check_output(
            ['docker', 'ps', '--format', '{{.Image}} {{.Ports}}'],
            stderr=subprocess.STDOUT
        )
        lines = output.decode().splitlines()
        for line in lines:
            if '->' in line:
                parts = line.split()
                image = parts[0]
                for part in parts[1:]:
                    if '->' in part:
                        try:
                            host_port = int(part.split('->')[0].split(':')[-1])
                            docker_ports[host_port] = image
                        except ValueError:
                            continue  # 포트 파싱 실패 시 무시
    except subprocess.CalledProcessError as e:
        print("[WARN] docker ps 명령 실패. 도커 환경 아님일 수 있음:", e.output.decode())
    except FileNotFoundError:
        print("[WARN] docker 명령어를 찾을 수 없습니다. 도커가 설치되어 있지 않거나 PATH에 없습니다.")
    except Exception as e:
        print(f"[WARN] Docker 정보 수집 중 예외 발생: {e}")
    return docker_ports