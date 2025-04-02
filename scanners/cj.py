import socket
from contextlib import closing

TIMEOUT = 3

# NetBIOS (port 139)
def netbios_port_scan(ip):
    port = 139
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode(errors='ignore')
            except:
                banner = ""
            return {'port': port, 'protocol': 'NetBIOS', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'NetBIOS', 'status': 'closed', 'message': str(e)}

# Redis (port 6379)
def redis_port_scan(ip):
    port = 6379
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            s.sendall(b"PING\r\n")
            banner = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'Redis', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'Redis', 'status': 'closed', 'message': str(e)}

# MongoDB (port 27017)
def mongodb_port_scan(ip):
    port = 27017
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            return {'port': port, 'protocol': 'MongoDB', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'MongoDB', 'status': 'closed', 'message': str(e)}

# PostgreSQL (port 5432)
def postgresql_port_scan(ip):
    port = 5432
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            return {'port': port, 'protocol': 'PostgreSQL', 'status': 'open'}
    except Exception as e:
        return {'port': port, 'protocol': 'PostgreSQL', 'status': 'closed', 'message': str(e)}

# Oracle (port 1521)
def oracle_port_scan(ip):
    port = 1521
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode(errors='ignore')
            except:
                banner = ""
            return {'port': port, 'protocol': 'Oracle', 'status': 'open', 'banner': banner.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'Oracle', 'status': 'closed', 'message': str(e)}

# Elasticsearch (port 9200)
def elasticsearch_port_scan(ip):
    port = 9200
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            resp = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'Elasticsearch', 'status': 'open', 'banner': resp.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'Elasticsearch', 'status': 'closed', 'message': str(e)}

# ZooKeeper (port 2181)
def zookeeper_port_scan(ip):
    port = 2181
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            s.sendall(b"stat\n")
            resp = s.recv(1024).decode(errors='ignore')
            return {'port': port, 'protocol': 'ZooKeeper', 'status': 'open', 'banner': resp.strip()}
    except Exception as e:
        return {'port': port, 'protocol': 'ZooKeeper', 'status': 'closed', 'message': str(e)}
