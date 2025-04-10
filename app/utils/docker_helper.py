import subprocess
import json
import re

SERVICE_KEYWORDS = {
    'tomcat': ['tomcat'],
    'jenkins': ['jenkins'],
    'gitlab': ['gitlab'],
    'mysql': ['mysql'],
    'postgres': ['postgres', 'pgsql'],
    'mongodb': ['mongo'],
    'redis': ['redis'],
    'elasticsearch': ['elasticsearch'],
    'kibana': ['kibana'],
    'zookeeper': ['zookeeper'],
    'consul': ['consul'],
    'etcd': ['etcd'],
    'vnc': ['vnc'],
    'ftp': ['ftp'],
    'ssh': ['ssh'],
    'nginx': ['nginx'],
    'apache': ['apache', 'httpd'],
    'docker': ['docker'],
    'kubernetes': ['k8s', 'kubernetes']
}

def detect_service_from_metadata(image, cmd, labels):
    try:
        text_pool = f"{image} {cmd} {json.dumps(labels)}".lower()
    except Exception as e:
        print(f"[WARN] 서비스 추정 중 텍스트 풀 생성 실패: {e}")
        return 'unknown'

    for service, keywords in SERVICE_KEYWORDS.items():
        if any(keyword in text_pool for keyword in keywords):
            return service

    return 'unknown'


def get_docker_port_image_map():
    docker_map = {}
    try:
        output = subprocess.check_output(['docker', 'ps', '-q'], stderr=subprocess.STDOUT)
        container_ids = output.decode().splitlines()

        for cid in container_ids:
            inspect = subprocess.check_output(['docker', 'inspect', cid])
            info = json.loads(inspect)[0]

            image = info.get("Config", {}).get("Image", "")
            cmd = " ".join(info.get("Config", {}).get("Cmd", []))
            labels = info.get("Config", {}).get("Labels", {})
            ports = info.get("NetworkSettings", {}).get("Ports", {})

            service = detect_service_from_metadata(image, cmd, labels)

            for container_port, bindings in ports.items():
                if bindings:
                    for b in bindings:
                        try:
                            host_port = int(b.get("HostPort", 0))
                            if host_port > 0:
                                docker_map[host_port] = (image, service)
                        except (ValueError, TypeError) as e:
                            print(f"[WARN] 호스트 포트 파싱 실패: {b} / 오류: {e}")
    except Exception as e:
        print(f"[WARN] 도커 포트 매핑 오류: {e}")

    return docker_map

