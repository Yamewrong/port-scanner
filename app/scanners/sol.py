import socket
from contextlib import closing

TIMEOUT = 3

def pop3_port_scan(ip):
    port = 110
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'POP3', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'POP3', 'status': 'closed', 'message': str(e)}

def imap_port_scan(ip):
    port = 143
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'IMAP', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'IMAP', 'status': 'closed', 'message': str(e)}

def ntp_port_scan(ip):
    port = 123
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            return {'port': port, 'protocol': 'NTP', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'NTP', 'status': 'closed', 'message': str(e)}

def snmp_port_scan(ip):
    port = 161
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            return {'port': port, 'protocol': 'SNMP', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'SNMP', 'status': 'closed', 'message': str(e)}

def ldap_port_scan(ip):
    port = 389
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            return {'port': port, 'protocol': 'LDAP', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'LDAP', 'status': 'closed', 'message': str(e)}

def smb_port_scan(ip):
    port = 445
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            return {'port': port, 'protocol': 'SMB', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'SMB', 'status': 'closed', 'message': str(e)}

def mysql_port_scan(ip):
    port = 3306
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'MySQL', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'MySQL', 'status': 'closed', 'message': str(e)}

def rdp_port_scan(ip):
    port = 3389
    try:
        with closing(socket.create_connection((ip, port), timeout=TIMEOUT)) as s:
            s.sendall(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
            data = s.recv(1024)
            return {'port': port, 'protocol': 'RDP', 'status': 'open', 'response': data.hex()}
    except Exception as e:
        return {'port': port, 'protocol': 'RDP', 'status': 'closed', 'message': str(e)}
