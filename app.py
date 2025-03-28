from flask import Flask, render_template, request, send_file, jsonify
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import time
from scanners import protocol_scanners  # 추가된 모듈 import

app = Flask(__name__)

# 마지막 스캔 결과 저장용 전역 변수
last_scan_result = {}

HIGH_RISK_PORTS = {
    21: "FTP - 인증 우회 및 평문 전송 취약점",
    23: "Telnet - 평문 전송 및 원격 쉘 취약점",
    445: "SMB - EternalBlue 등 취약점 다수",
    3389: "RDP - 무차별 대입, CVE 취약점 다수",
    3306: "MySQL - 인증 우회, DB 접근 취약점",
    139: "NetBIOS - 내부 공유 노출 가능"
}

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return {'port': port, 'status': 'open'}
            else:
                return {'port': port, 'status': 'closed'}
    except socket.gaierror:
        return {'port': port, 'status': 'error', 'message': '호스트 이름을 확인할 수 없음'}
    except Exception as e:
        return {'port': port, 'status': 'error', 'message': str(e)}

def analyze_risks(open_ports):
    warnings = []
    if 443 in open_ports and len(open_ports) > 1:
        warnings.append("⚠ HTTPS 외 포트가 열려 있습니다. 최소 포트 오픈 정책을 확인하세요.")
    db_ports = {3306, 1433, 5432, 1521}
    exposed_db = [port for port in open_ports if port in db_ports]
    if exposed_db:
        warnings.append(f"⚠ DB 관련 포트가 열려 있습니다: {', '.join(map(str, exposed_db))}")
    return warnings

def analyze_vulnerabilities(results):
    for r in results:
        if r['status'] == 'open' and r['port'] in HIGH_RISK_PORTS:
            r['vuln_warning'] = HIGH_RISK_PORTS[r['port']]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    if not target:
        return render_template('index.html', error="대상 IP 또는 도메인을 입력하세요.")

    ports = range(1, 1025)
    open_ports = []
    scan_results = []
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(check_port, target, port): port for port in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                scan_results.append(result)
                if result['status'] == 'open':
                    open_ports.append(result['port'])
    except Exception as e:
        return render_template('index.html', error=str(e))

    scan_time = round(time.time() - start_time, 2)
    scan_results.sort(key=lambda x: x['port'])
    analyze_vulnerabilities(scan_results)
    warnings = analyze_risks(open_ports)

    global last_scan_result
    last_scan_result = {
        'ip': target,
        'ports': open_ports,
        'scan_time': scan_time,
        'results': scan_results,
        'warnings': warnings
    }

    return render_template('result.html', result=last_scan_result)

@app.route('/fullscan', methods=['POST'])
def full_scan():
    ip = request.form.get('target', '').strip()
    if not ip:
        return render_template('index.html', error="대상 IP를 입력하세요.")

    scan_functions = [
        protocol_scanners.ftp_port_scan,
        protocol_scanners.ssh_port_scan,
        protocol_scanners.telnet_port_scan,
        lambda ip: protocol_scanners.smtp_port_scan(ip, 25),
        lambda ip: protocol_scanners.smtp_port_scan(ip, 587),
        protocol_scanners.dns_port_scan,
        protocol_scanners.http_port_scan,
        protocol_scanners.pop3_port_scan,
        protocol_scanners.ntp_port_scan,
        protocol_scanners.imap_port_scan,
        protocol_scanners.snmp_port_scan,
        protocol_scanners.ldap_port_scan,
        protocol_scanners.https_port_scan,
        protocol_scanners.smb_port_scan,
        protocol_scanners.mysql_port_scan,
        protocol_scanners.rdp_port_scan
    ]

    start_time = time.time()
    results = [func(ip) for func in scan_functions]
    scan_time = round(time.time() - start_time, 2)
    open_ports = [r['port'] for r in results if r['status'] == 'open']
    analyze_vulnerabilities(results)
    warnings = analyze_risks(open_ports)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'scan_time': scan_time,
        'results': results,
        'ports': open_ports,
        'warnings': warnings
    }

    return render_template('result.html', result=last_scan_result)

@app.route('/customscan', methods=['POST'])
def custom_scan():
    ip = request.form.get('target', '').strip()
    selected_protocols = request.form.getlist('protocols')

    if not ip or not selected_protocols:
        return render_template('index.html', error="대상 IP와 프로토콜을 선택하세요.")

    scanner_map = {
        'ftp': protocol_scanners.ftp_port_scan,
        'ssh': protocol_scanners.ssh_port_scan,
        'telnet': protocol_scanners.telnet_port_scan,
        'smtp': lambda ip: protocol_scanners.smtp_port_scan(ip, 25),
        'smtp_tls': lambda ip: protocol_scanners.smtp_port_scan(ip, 587),
        'dns': protocol_scanners.dns_port_scan,
        'http': protocol_scanners.http_port_scan,
        'pop3': protocol_scanners.pop3_port_scan,
        'ntp': protocol_scanners.ntp_port_scan,
        'imap': protocol_scanners.imap_port_scan,
        'snmp': protocol_scanners.snmp_port_scan,
        'ldap': protocol_scanners.ldap_port_scan,
        'https': protocol_scanners.https_port_scan,
        'smb': protocol_scanners.smb_port_scan,
        'mysql': protocol_scanners.mysql_port_scan,
        'rdp': protocol_scanners.rdp_port_scan
    }

    start_time = time.time()
    results = []
    for proto in selected_protocols:
        func = scanner_map.get(proto)
        if func:
            results.append(func(ip))

    scan_time = round(time.time() - start_time, 2)
    open_ports = [r['port'] for r in results if r['status'] == 'open']
    analyze_vulnerabilities(results)
    warnings = analyze_risks(open_ports)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'scan_time': scan_time,
        'results': results,
        'ports': open_ports,
        'warnings': warnings
    }

    return render_template('result.html', result=last_scan_result)

@app.route('/download')
def download():
    if not last_scan_result:
        return "아직 스캔 결과가 없습니다.", 400

    ip = last_scan_result.get('ip', 'unknown')
    scan_time = last_scan_result.get('scan_time', 0)
    results = last_scan_result.get('results', [])

    content = f"\U0001F4C4 포트 스캔 보고서\n대상: {ip}\n소요 시간: {scan_time}초\n\n결과:\n"
    for r in results:
        status_text = "열림" if r['status'] == 'open' else "닫힘" if r['status'] == 'closed' else f"오류: {r.get('message', '')}"
        content += f"- {r.get('protocol', '')} (포트 {r['port']}): {status_text}\n"
        if 'vuln_warning' in r:
            content += f"  >> 위험: {r['vuln_warning']}\n"

    buffer = io.BytesIO()
    buffer.write(content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype='text/plain', as_attachment=True, download_name='scan_report.txt')

if __name__ == '__main__':
    app.run(debug=True)
