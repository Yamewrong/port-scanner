from flask import Flask, render_template, request, send_file
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from screenshot_utils import capture_web_info
import requests
import io
import time
import subprocess
import os

# 각 팀원 스캐너 모듈 import
from scanners import my  # kubernetes, docker 등
from scanners import sol  # pop3, imap 등
from scanners import cj   # redis, mongodb 등
from scanners import ajs   # ftp, ssh 등

app = Flask(__name__)

last_scan_result = {}
SHODAN_API_KEY = '00eHpdt1Ww1SNP73fvPMytb5xvOLPyRb'
HIGH_RISK_PORTS = {
    21: "FTP - 인증 우회 및 평문 전송 취약점",
    23: "Telnet - 평문 전송 및 원격 쉘 취약점",
    445: "SMB - EternalBlue 등 취약점 다수",
    3389: "RDP - 무차별 대입, CVE 취약점 다수",
    3306: "MySQL - 인증 우회, DB 접근 취약점",
    139: "NetBIOS - 내부 공유 노출 가능"
}

EXTERNAL_RISK_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    445: "SMB",
    139: "NetBIOS",
    3389: "RDP",
    23: "Telnet",
    21: "FTP"
}

def resolve_domain(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def get_shodan_cves(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        data = response.json()
        return list(data.get('vulns', []))
    except:
        return []

def get_epss_score(cve_id):
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        res = requests.get(url)
        data = res.json()
        if data['data']:
            return float(data['data'][0]['epss'])
        return 0.0
    except:
        return 0.0

def run_nuclei_scan(ip, open_ports):
    cve_results = []

    for port in open_ports:
        url = f"http://{ip}:{port}"
        cmd = [
            "C:\\Users\\susud\\scoop\\apps\\nuclei\\current\\nuclei.exe",
            "-u", url,
            "-t", "C:\\Users\\susud\\nuclei-templates",
            "-tags", "cve",
            "-silent"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout.strip().splitlines()

            print(f"[DEBUG] Executing nuclei for {url}")
            print("[DEBUG nuclei output]:", output)

            for line in output:
                if "CVE-" in line:
                    cve_results.append(line)

        except subprocess.TimeoutExpired:
            print(f"[ERROR] Nuclei timeout for {url}")
        except Exception as e:
            print(f"[ERROR] Nuclei failed for {url}: {e}")

    return list(set(cve_results))





def analyze_cve_risks(ip, open_ports):
    print(f"[DEBUG] Running CVE analysis for {ip}:{open_ports}")
    raw_results = run_nuclei_scan(ip, open_ports)
    print("[DEBUG] Discovered CVEs (raw):", raw_results)

    analyzed = []
    for line in raw_results:
        if "CVE-" in line:
            cve_id = extract_cve_id(line)
            epss = get_epss_score(cve_id)
            if epss >= 0.7:
                severity = "🟥 고위험"
            elif epss >= 0.4:
                severity = "🟧 중간위험"
            else:
                severity = "🟨 저위험"
            analyzed.append(f"{severity} | {cve_id} (EPSS: {epss:.2f})")
        else:
            analyzed.append(f"ℹ️ Info: {line}")

    print("[DEBUG] Final CVE Warnings:", analyzed)
    return analyzed


def extract_cve_id(text):
    import re
    match = re.search(r"CVE-\d{4}-\d{4,7}", text)
    return match.group(0) if match else "CVE-Unknown"




def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return {'port': port, 'status': 'open' if s.connect_ex((ip, port)) == 0 else 'closed'}
    except Exception as e:
        return {'port': port, 'status': 'error', 'message': str(e)}

def analyze_risks(open_ports):
    warnings = []
    db_ports = {3306, 1433, 5432, 1521}
    exposed_db = [port for port in open_ports if port in db_ports]

    if 443 in open_ports and len(open_ports) > 1:
        warnings.append("⚠ HTTPS 외 포트가 함께 열려 있습니다. 최소 오픈 정책을 확인하세요.")
    if 80 in open_ports and 443 in open_ports:
        warnings.append("⚠ HTTP와 HTTPS가 모두 열려 있습니다. HTTP 접근 차단을 고려하세요.")
    if 21 in open_ports and 445 in open_ports:
        warnings.append("⚠ FTP와 SMB가 동시에 열려 있습니다. 내부 파일 유출 가능성이 있습니다.")
    if len(exposed_db) >= 2:
        warnings.append("🚨 다중 DB 포트가 동시에 열려 있습니다. 보안 리스크가 큽니다!")
    if 6379 in open_ports or 27017 in open_ports:
        warnings.append("⚠ Redis 또는 MongoDB가 열려 있습니다. 인증 미설정 여부 확인 필요.")

    if exposed_db:
        warnings.append(f"⚠ 외부에 DB 포트가 열려 있습니다: {', '.join(map(str, exposed_db))}")

    return warnings

def analyze_vulnerabilities(results):
    for r in results:
        if r['status'] == 'open' and r['port'] in HIGH_RISK_PORTS:
            r['vuln_warning'] = HIGH_RISK_PORTS[r['port']]

def detect_asset_exposure(open_ports):
    return [f"\U0001F513 외부에서 {EXTERNAL_RISK_PORTS[p]} 포트({p})가 열려 있습니다. 민감 자산 노출 위험이 있습니다."
            for p in open_ports if p in EXTERNAL_RISK_PORTS]

def detect_unauthorized_access(ip, open_ports):
    warnings = []
    if 6379 in open_ports:
        try:
            s = socket.create_connection((ip, 6379), timeout=2)
            s.sendall(b'PING\r\n')
            if b'PONG' in s.recv(1024):
                warnings.append("\U0001F6A8 Redis 인증 없이 접속 가능합니다. 즉시 차단 또는 보안 설정이 필요합니다.")
            s.close()
        except: pass
    if 27017 in open_ports:
        try:
            s = socket.create_connection((ip, 27017), timeout=2)
            s.sendall(b'\x3a\x00\x00\x00\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00isMaster\x00\x00')
            if b'ok' in s.recv(1024):
                warnings.append("\U0001F6A8 MongoDB 인증 없이 외부 접속이 가능합니다.")
            s.close()
        except: pass
    if 9200 in open_ports:
        try:
            res = requests.get(f"http://{ip}:9200", timeout=2)
            if res.status_code == 200 and "cluster_name" in res.text:
                warnings.append("\U0001F6A8 Elasticsearch가 인증 없이 노출되어 있습니다.")
        except: pass
    return warnings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    ip = resolve_domain(target)
    if not ip:
        return render_template('index.html', error="도메인 또는 IP를 확인할 수 없습니다.")

    ports = range(1, 1025)
    open_ports = []
    scan_results = []
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(check_port, ip, port): port for port in ports}
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
    cve_warnings = analyze_cve_risks(ip, open_ports)
    warnings += cve_warnings
    warnings += detect_asset_exposure(open_ports)
    warnings += detect_unauthorized_access(ip, open_ports)
    web_infos = capture_web_info(target)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'hostname': target,
        'ports': open_ports,
        'scan_time': scan_time,
        'results': scan_results,
        'warnings': warnings,
        'cve_warnings': cve_warnings,
        'web_infos': web_infos
    }

    return render_template('result.html', result=last_scan_result)

@app.route('/customscan', methods=['POST'])
def custom_scan():
    target = request.form.get('target', '').strip()
    selected_protocols = request.form.getlist('protocols')
    start_time = time.time()

    if not target or not selected_protocols:
        return render_template('index.html', error="대상 IP와 프로토콜을 선택하세요.")

    ip = resolve_domain(target)
    if not ip:
        return render_template('index.html', error="도메인 또는 IP를 확인할 수 없습니다.")

    scanner_map = {
        'ftp': ajs.scan_ftp,
        'ssh': ajs.scan_ssh,
        'http': ajs.scan_http,
        'https': ajs.scan_https,
        'dns': ajs.scan_dns,
        'pop3': sol.pop3_port_scan,
        'imap': sol.imap_port_scan,
        'ntp': sol.ntp_port_scan,
        'snmp': sol.snmp_port_scan,
        'ldap': sol.ldap_port_scan,
        'smb': sol.smb_port_scan,
        'mysql': sol.mysql_port_scan,
        'rdp': sol.rdp_port_scan,
        'kubernetes': my.scan_kubernetes,
        'docker': my.scan_docker,
        'etcd': my.scan_etcd,
        'consul': my.scan_consul,
        'jenkins': my.scan_jenkins,
        'gitlab': my.scan_gitlab,
        'vnc': my.scan_vnc,
        'tftp': my.scan_tftp,
        'netbios': cj.netbios_port_scan,
        'redis': cj.redis_port_scan,
        'mongodb': cj.mongodb_port_scan,
        'postgresql': cj.postgresql_port_scan,
        'oracle': cj.oracle_port_scan,
        'elasticsearch': cj.elasticsearch_port_scan,
        'zookeeper': cj.zookeeper_port_scan
    }

    results = []
    for proto in selected_protocols:
        func = scanner_map.get(proto)
        if func:
            results.append(func(ip))

    open_ports = [r['port'] for r in results if r['status'] == 'open']
    scan_time = round(time.time() - start_time, 2)

    analyze_vulnerabilities(results)
    warnings = analyze_risks(open_ports)
    cve_warnings = analyze_cve_risks(ip, open_ports)
    warnings += cve_warnings
    warnings += detect_asset_exposure(open_ports)
    warnings += detect_unauthorized_access(ip, open_ports)
    web_infos = capture_web_info(target)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'hostname': target,
        'ports': open_ports,
        'scan_time': scan_time,
        'results': results,
        'warnings': warnings,
        'cve_warnings': cve_warnings,
        'web_infos': web_infos
    }

    return render_template('result.html', result=last_scan_result)


@app.route('/download')
def download():
    if not last_scan_result:
        return "아직 스캔 결과가 없습니다.", 400

    ip = last_scan_result.get('ip', 'unknown')
    scan_time = last_scan_result.get('scan_time', 0)
    results = last_scan_result.get('results', [])

    content = f"\U0001F4C4 포트 스캔 보고서\n대상 IP: {ip}\n소요 시간: {scan_time}초\n\n결과:\n"
    for r in results:
        status_text = "열림" if r['status'] == 'open' else "닫힘" if r['status'] == 'closed' else f"오류: {r.get('message', '')}"
        content += f"- 포트 {r['port']}: {status_text}\n"
        if 'vuln_warning' in r:
            content += f"  >> 위협: {r['vuln_warning']}\n"

    buffer = io.BytesIO()
    buffer.write(content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype='text/plain', as_attachment=True, download_name='scan_report.txt')

if __name__ == '__main__':
    app.run(debug=True)
