import requests
import socket
from contextlib import closing

TIMEOUT = 3
def scan_telnet(ip):
    import socket
    port = 23
    try:
        s = socket.create_connection((ip, port), timeout=2)
        banner = s.recv(1024)
        
        try:
            decoded = banner.decode('utf-8', errors='replace')
        except:
            decoded = str(banner)

        # 🌟 서비스 추정 추가
        if 'login:' in decoded.lower():
            service_guess = 'Unix Shell'
        elif 'telnet' in decoded.lower():
            service_guess = 'Telnet Server'
        elif '%' in decoded:
            service_guess = 'Cisco 장비 또는 커맨드쉘'
        else:
            service_guess = 'Unknown'

        return {
            'protocol': 'telnet',
            'port': port,
            'status': 'open',
            'banner': decoded.strip(),
            'service_guess': service_guess
        }

    except Exception as e:
        return {'protocol': 'telnet', 'port': port, 'status': 'closed', 'message': str(e)}

def scan_ftp(ip):
    port = 21
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            response = sock.recv(1024).decode('utf-8')
            return {'protocol': 'ftp', 'port': port, 'status': 'open', 'info': response}
    except Exception as e:
        return {'protocol': 'ftp', 'port': port, 'status': 'closed', 'message': str(e)}

def scan_ssh(ip):
    port = 22
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            response = sock.recv(1024).decode('utf-8')
            return {'protocol': 'ssh', 'port': port, 'status': 'open', 'info': response}
    except Exception as e:
        return {'protocol': 'ssh', 'port': port, 'status': 'closed', 'message': str(e)}

def scan_http(ip):
    port = 80
    try:
        response = requests.get(f'http://{ip}:{port}', timeout=TIMEOUT)
        if '<title>' in response.text:
            title = response.text.split('<title>')[1].split('</title>')[0]
        else:
            title = 'No Title'
        return {'protocol': 'http', 'port': port, 'status': 'open', 'info': title}
    except Exception as e:
        return {'protocol': 'http', 'port': port, 'status': 'closed', 'message': str(e)}

def scan_https(ip):
    port = 443
    try:
        response = requests.get(f'https://{ip}:{port}', timeout=TIMEOUT, verify=False)
        if '<title>' in response.text:
            title = response.text.split('<title>')[1].split('</title>')[0]
        else:
            title = 'No Title'
        return {'protocol': 'https', 'port': port, 'status': 'open', 'info': title}
    except Exception as e:
        return {'protocol': 'https', 'port': port, 'status': 'closed', 'message': str(e)}

def scan_dns(ip):
    port = 53
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(TIMEOUT)
            # DNS standard query to example.com
            query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            sock.sendto(query, (ip, port))
            response = sock.recv(1024)
            return {'protocol': 'dns', 'port': port, 'status': 'open', 'info': response.hex()}
    except Exception as e:
        return {'protocol': 'dns', 'port': port, 'status': 'closed', 'message': str(e)}