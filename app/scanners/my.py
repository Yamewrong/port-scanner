import socket
import requests
from contextlib import closing

TIMEOUT = 3

# Kubernetes API Server
def scan_kubernetes(ip):
    port = 6443
    try:
        response = requests.get(f"https://{ip}:{port}", verify=False, timeout=TIMEOUT)
        return {'protocol': 'kubernetes', 'port': port, 'status': 'open', 'response': response.text[:200]}
    except Exception as e:
        return {'protocol': 'kubernetes', 'port': port, 'status': 'closed', 'message': str(e)}

# Docker Remote API
def scan_docker(ip):
    port = 2375
    try:
        response = requests.get(f"http://{ip}:{port}/version", timeout=TIMEOUT)
        return {'protocol': 'docker', 'port': port, 'status': 'open', 'response': response.text}
    except Exception as e:
        return {'protocol': 'docker', 'port': port, 'status': 'closed', 'message': str(e)}

# etcd Key-Value Store
def scan_etcd(ip):
    port = 2379
    try:
        response = requests.get(f"http://{ip}:{port}/version", timeout=TIMEOUT)
        return {'protocol': 'etcd', 'port': port, 'status': 'open', 'response': response.text}
    except Exception as e:
        return {'protocol': 'etcd', 'port': port, 'status': 'closed', 'message': str(e)}

# Consul Service Discovery
def scan_consul(ip):
    port = 8500
    try:
        response = requests.get(f"http://{ip}:{port}/v1/agent/self", timeout=TIMEOUT)
        return {'protocol': 'consul', 'port': port, 'status': 'open', 'response': response.text[:200]}
    except Exception as e:
        return {'protocol': 'consul', 'port': port, 'status': 'closed', 'message': str(e)}

# Jenkins
def scan_jenkins(ip):
    port = 8080
    try:
        response = requests.get(f"http://{ip}:{port}", timeout=TIMEOUT)
        return {'protocol': 'jenkins', 'port': port, 'status': 'open', 'response': response.text[:200]}
    except Exception as e:
        return {'protocol': 'jenkins', 'port': port, 'status': 'closed', 'message': str(e)}

# GitLab
def scan_gitlab(ip):
    port = 80  # 또는 443
    try:
        response = requests.get(f"http://{ip}:{port}/users/sign_in", timeout=TIMEOUT)
        return {'protocol': 'gitlab', 'port': port, 'status': 'open', 'response': response.text[:200]}
    except Exception as e:
        return {'protocol': 'gitlab', 'port': port, 'status': 'closed', 'message': str(e)}

# VNC
def scan_vnc(ip):
    port = 5900
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors='ignore')
            return {'protocol': 'vnc', 'port': port, 'status': 'open', 'banner': banner}
    except Exception as e:
        return {'protocol': 'vnc', 'port': port, 'status': 'closed', 'message': str(e)}

# TFTP (UDP)
def scan_tftp(ip):
    port = 69
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(TIMEOUT)
            # TFTP RRQ packet (read request for test.txt)
            packet = b"\x00\x01test.txt\x00octet\x00"
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(1024)
            return {'protocol': 'tftp', 'port': port, 'status': 'open', 'response': data.hex()}
    except Exception as e:
        return {'protocol': 'tftp', 'port': port, 'status': 'closed', 'message': str(e)}
