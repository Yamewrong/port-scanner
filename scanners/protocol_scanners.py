import socket
import ssl
import struct

# 공통 TCP 스캔 베이스

def tcp_connect(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return s
    except Exception as e:
        return None

# FTP (port 21)
def ftp_port_scan(ip):
    try:
        with tcp_connect(ip, 21) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 21, 'protocol': 'FTP', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 21, 'protocol': 'FTP', 'status': 'closed'}

# SSH (port 22)
def ssh_port_scan(ip):
    try:
        with tcp_connect(ip, 22) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 22, 'protocol': 'SSH', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 22, 'protocol': 'SSH', 'status': 'closed'}

# Telnet (port 23)
def telnet_port_scan(ip):
    try:
        with tcp_connect(ip, 23) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 23, 'protocol': 'Telnet', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 23, 'protocol': 'Telnet', 'status': 'closed'}

# SMTP (port 25, 587)
def smtp_port_scan(ip, port=25):
    try:
        with tcp_connect(ip, port) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'SMTP', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': port, 'protocol': 'SMTP', 'status': 'closed'}

# DNS (UDP port 53)
def dns_port_scan(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                + b'\x03www\x06google\x03com\x00\x00\x01\x00\x01'
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(512)
        return {'port': 53, 'protocol': 'DNS', 'status': 'open'}
    except:
        return {'port': 53, 'protocol': 'DNS', 'status': 'closed'}

# HTTP (port 80)
def http_port_scan(ip):
    try:
        with tcp_connect(ip, 80) as s:
            s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
            resp = s.recv(1024).decode(errors='ignore')
            return {'port': 80, 'protocol': 'HTTP', 'status': 'open', 'banner': resp.strip()}
    except:
        return {'port': 80, 'protocol': 'HTTP', 'status': 'closed'}

# HTTPS (port 443)
def https_port_scan(ip):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return {'port': 443, 'protocol': 'HTTPS', 'status': 'open', 'cert': cert}
    except:
        return {'port': 443, 'protocol': 'HTTPS', 'status': 'closed'}

# POP3 (port 110)
def pop3_port_scan(ip):
    try:
        with tcp_connect(ip, 110) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 110, 'protocol': 'POP3', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 110, 'protocol': 'POP3', 'status': 'closed'}

# IMAP (port 143)
def imap_port_scan(ip):
    try:
        with tcp_connect(ip, 143) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 143, 'protocol': 'IMAP', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 143, 'protocol': 'IMAP', 'status': 'closed'}

# NTP (UDP port 123)
def ntp_port_scan(ip):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        msg = b'\x1b' + 47 * b'\0'
        client.sendto(msg, (ip, 123))
        client.recvfrom(512)
        return {'port': 123, 'protocol': 'NTP', 'status': 'open'}
    except:
        return {'port': 123, 'protocol': 'NTP', 'status': 'closed'}

# SNMP (UDP port 161)
def snmp_port_scan(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        msg = b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
        sock.sendto(msg, (ip, 161))
        sock.recvfrom(512)
        return {'port': 161, 'protocol': 'SNMP', 'status': 'open'}
    except:
        return {'port': 161, 'protocol': 'SNMP', 'status': 'closed'}

# LDAP (port 389)
def ldap_port_scan(ip):
    try:
        with tcp_connect(ip, 389) as s:
            return {'port': 389, 'protocol': 'LDAP', 'status': 'open'}
    except:
        return {'port': 389, 'protocol': 'LDAP', 'status': 'closed'}

# SMB (port 445)
def smb_port_scan(ip):
    try:
        with tcp_connect(ip, 445) as s:
            return {'port': 445, 'protocol': 'SMB', 'status': 'open'}
    except:
        return {'port': 445, 'protocol': 'SMB', 'status': 'closed'}

# MySQL (port 3306)
def mysql_port_scan(ip):
    try:
        with tcp_connect(ip, 3306) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': 3306, 'protocol': 'MySQL', 'status': 'open', 'banner': banner.strip()}
    except:
        return {'port': 3306, 'protocol': 'MySQL', 'status': 'closed'}

# RDP (port 3389)
def rdp_port_scan(ip):
    try:
        with tcp_connect(ip, 3389) as s:
            s.sendall(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
            resp = s.recv(1024)
            return {'port': 3389, 'protocol': 'RDP', 'status': 'open', 'response': resp.hex()}
    except:
        return {'port': 3389, 'protocol': 'RDP', 'status': 'closed'}
