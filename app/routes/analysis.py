from flask import Blueprint, render_template, request
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket, time, os, json, re
import requests, io
from app.utils.nuclei_helper import run_nuclei_scan
from app.utils.shodan_helper import search_shodan
from app.utils.screenshot_helper import take_screenshot
from app.utils.screenshot_utils import capture_web_info
from app.utils.docker_helper import get_docker_port_image_map
from app.utils.infer_service_from_image import infer_service_from_image
from app.utils.trivy_helper import scan_with_trivy
from app.utils.external_helper import guess_service_from_banner
from app.utils.ansible_helper import check_docker_installed
from app.utils.epss_helper import get_epss_scores
from app.utils.guideline_generator import generate_guidelines_from_vulns
from app.utils.epss_graph_helper import generate_epss_histogram, generate_epss_chart

analysis_bp = Blueprint('analysis', __name__)

last_scan_result = {}

HIGH_RISK_PORTS = {
    21: "FTP - 인증 우회 및 평문 전송 취약점",
    23: "Telnet - 평문 전송 및 원격 셔널 취약점",
    445: "SMB - EternalBlue 등 취약점 다수",
    3389: "RDP - 무차리 대입, CVE 취약점 다수",
    3306: "MySQL - 인증 우회, DB 접근 취약점",
    139: "NetBIOS - 내부 공유 노출 가능"
}

EXTERNAL_RISK_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    445: "SMB", 139: "NetBIOS", 3389: "RDP", 23: "Telnet", 21: "FTP"
}

SHODAN_API_KEY = '00eHpdt1Ww1SNP73fvPMytb5xvOLPyRb'

def resolve_domain(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return {'port': port, 'status': 'open' if s.connect_ex((ip, port)) == 0 else 'closed'}
    except Exception as e:
        return {'port': port, 'status': 'error', 'message': str(e)}

def analyze_vulnerabilities(results):
    for r in results:
        if r['status'] == 'open' and r['port'] in HIGH_RISK_PORTS:
            r['vuln_warning'] = HIGH_RISK_PORTS[r['port']]

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

def detect_asset_exposure(open_ports):
    return [f"🔓 외부에서 {EXTERNAL_RISK_PORTS[p]} 포트({p})가 열려 있습니다. 민감 자산 노출 위험이 있습니다."
            for p in open_ports if p in EXTERNAL_RISK_PORTS]

def detect_unauthorized_access(ip, open_ports):
    warnings = []
    if 6379 in open_ports:
        try:
            s = socket.create_connection((ip, 6379), timeout=2)
            s.sendall(b'PING\r\n')
            if b'PONG' in s.recv(1024):
                warnings.append("🚨 Redis 인증 없이 접속 가능합니다. 즉시 차단 또는 보안 설정이 필요합니다.")
            s.close()
        except: pass
    if 27017 in open_ports:
        try:
            s = socket.create_connection((ip, 27017), timeout=2)
            s.sendall(b'\x3a\x00\x00\x00\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00isMaster\x00\x00')
            if b'ok' in s.recv(1024):
                warnings.append("🚨 MongoDB 인증 없이 외부 접속이 가능합니다.")
            s.close()
        except: pass
    if 9200 in open_ports:
        try:
            res = requests.get(f"http://{ip}:9200", timeout=2)
            if res.status_code == 200 and "cluster_name" in res.text:
                warnings.append("🚨 Elasticsearch가 인증 없이 노출되어 있습니다.")
        except: pass
    return warnings

def enrich_with_trivy(ip, results, is_docker=True):
    if not is_docker:
        return

    docker_map = get_docker_port_image_map() if is_docker else {}

    for r in results:
        port = r['port']
        if port in docker_map:
            image_name, service_name = docker_map[port]
            r['docker_image'] = image_name
            r['service_name'] = service_name or infer_service_from_image(image_name)

            try:
                safe_name = image_name.replace('/', '_').replace(':', '_')
                output_file = f"trivy_reports/{safe_name}.json"

                if not os.path.exists(output_file):
                    r['trivy_vulns'] = scan_with_trivy(image_name)
                else:
                    with open(output_file, encoding='utf-8') as f:
                        existing = json.load(f)

                    r['trivy_vulns'] = [
                        vuln
                        for result in existing.get("Results", [])
                        for vuln in result.get("Vulnerabilities", [])
                    ]
            except Exception as e:
                r['trivy_vulns'] = []
        else:
            r['trivy_vulns'] = []

@analysis_bp.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    ip = resolve_domain(target)

    pem_file = request.files.get('pem_file')
    ssh_user = request.form.get('ssh_user', '').strip()
    is_docker = request.form.get('is_docker') == 'on'

    if pem_file and ssh_user and ip:
        pem_path = f"/tmp/{time.time()}_temp.pem"
        pem_file.save(pem_path)
        try:
            is_docker = check_docker_installed(ip, ssh_user, pem_path)
        except:
            pass
        finally:
            os.remove(pem_path)

    if not ip:
        return render_template('ionendex.html', error="도메인 또는 IP를 확인할 수 없습니다.")

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

    scan_results.sort(key=lambda x: x['port'])
    analyze_vulnerabilities(scan_results)
    warnings = analyze_risks(open_ports)
    warnings += detect_asset_exposure(open_ports)
    warnings += detect_unauthorized_access(ip, open_ports)
    web_infos = capture_web_info(target)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'hostname': target,
        'ports': open_ports,
        'scan_time': round(time.time() - start_time, 2),
        'results': scan_results,
        'warnings': warnings,
        'web_infos': web_infos,
        'is_docker': is_docker
    }

    enrich_with_trivy(ip, scan_results, is_docker)
    nuclei_results = run_nuclei_scan(f"http://{target}")
    last_scan_result['nuclei_results'] = nuclei_results

    cves = list({vuln['id'] for r in scan_results if 'trivy_vulns' in r for vuln in r['trivy_vulns'] if 'id' in vuln})
    epss_scores = get_epss_scores(cves)
    last_scan_result['epss_scores'] = epss_scores
    all_trivy_vulns = [
        vuln for r in scan_results if 'trivy_vulns' in r
        for vuln in r['trivy_vulns']
        if 'VulnerabilityID' in vuln
    ]
    epss_values = [info["epss_score"] for info in epss_scores.values() if "epss_score" in info]

    hist_filename = f"epss_graphs/{ip}_hist.png"
    chart_filename = f"epss_graphs/{ip}_top10.png"

    histogram_path = generate_epss_histogram(epss_values, filename=f"{ip}_hist.png")
    bar_chart_path = generate_epss_chart(epss_scores, filename=f"{ip}_top10.png")

    last_scan_result["epss_graph"] = hist_filename
    last_scan_result["epss_chart"] = chart_filename

    print("✅ [DEBUG] result에 포함된 epss_graph:", last_scan_result["epss_graph"])
    print("✅ [DEBUG] result에 포함된 epss_chart:", last_scan_result["epss_chart"])

    cve_guidelines = generate_guidelines_from_vulns(all_trivy_vulns, epss_scores)
    last_scan_result['cve_guidelines'] = cve_guidelines

    shodan_data = search_shodan(SHODAN_API_KEY, ip)
    last_scan_result['shodan_info'] = shodan_data

    screenshot_path = f"static/screenshots/{ip}.png"
    take_screenshot(f"http://{target}", screenshot_path)
    last_scan_result['screenshot_path'] = screenshot_path
    print("✅ epss 그래프 경로:", last_scan_result["epss_graph"])
    print("📦 최종 전달되는 result keys:", last_scan_result.keys())
    return render_template('result.html', result=last_scan_result)