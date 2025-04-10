from flask import Blueprint, render_template, request
import time
from app.utils.ansible_helper import check_docker_installed
from app.utils.trivy_helper import enrich_with_trivy
from app.utils.screenshot_utils import capture_web_info
from app.utils.nuclei_helper import run_nuclei_scan
from app.utils.shodan_helper import search_shodan
from app.utils.epss_helper import get_epss_scores
from app.utils.epss_graph_helper import generate_epss_histogram, generate_epss_chart
from app.utils.guideline_generator import generate_guidelines_from_vulns
from app.scanners import ajs, sol, cj, my
from app.routes.analysis import (
    analyze_vulnerabilities,
    analyze_risks,
    detect_asset_exposure,
    detect_unauthorized_access
)

custom_scan_bp = Blueprint('custom_scan', __name__)

@custom_scan_bp.route('/customscan', methods=['POST'])
def custom_scan():
    target = request.form.get('target', '').strip()
    selected_protocols = request.form.getlist('protocols')
    is_docker = request.form.get('is_docker') == 'on'
    pem_file = request.files.get('pem_file')
    ssh_user = request.form.get('ssh_user', '').strip()

    if not target or not selected_protocols:
        return render_template('index.html', error="대상 IP와 프로토콜을 선택하세요.")

    import socket
    try:
        ip = socket.gethostbyname(target)
    except:
        return render_template('index.html', error="도메인 또는 IP를 확인할 수 없습니다.")

    if pem_file and ssh_user:
        pem_path = f"/tmp/{time.time()}_temp.pem"
        pem_file.save(pem_path)
        try:
            is_docker = check_docker_installed(ip, ssh_user, pem_path)
        except:
            pass
        finally:
            import os
            os.remove(pem_path)

    start_time = time.time()

    scanner_map = {
        'ftp': ajs.scan_ftp,
        'ssh': ajs.scan_ssh,
        'http': ajs.scan_http,
        'https': ajs.scan_https,
        'telnet': ajs.scan_telnet,
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

    enrich_with_trivy(ip, results, is_docker)

    docker_ports_info = {}
    for entry in results:
        if entry.get('docker_image'):
            docker_ports_info[entry['port']] = entry['docker_image']

    open_ports = [r['port'] for r in results if r['status'] == 'open']
    scan_time = round(time.time() - start_time, 2)

    analyze_vulnerabilities(results)
    warnings = analyze_risks(open_ports)
    warnings += detect_asset_exposure(open_ports)
    warnings += detect_unauthorized_access(ip, open_ports)
    web_infos = capture_web_info(target)

    nuclei_results = run_nuclei_scan(f"http://{target}")

    all_trivy_vulns = [
        vuln for r in results if 'trivy_vulns' in r
        for vuln in r['trivy_vulns']
        if 'VulnerabilityID' in vuln or 'id' in vuln
    ]

    cves = list({
        vuln.get('VulnerabilityID') or vuln.get('id')
        for vuln in all_trivy_vulns
    })

    epss_scores = get_epss_scores(cves)
    epss_values = [info["epss_score"] for info in epss_scores.values() if "epss_score" in info]

    histogram_path = generate_epss_histogram(epss_values, filename=f"{ip}_hist.png")
    bar_chart_path = generate_epss_chart(epss_scores, filename=f"{ip}_top25.png")

    cve_guidelines = generate_guidelines_from_vulns(all_trivy_vulns, epss_scores)

    global last_scan_result
    last_scan_result = {
        'ip': ip,
        'hostname': target,
        'ports': open_ports,
        'scan_time': scan_time,
        'results': results,
        'warnings': warnings,
        'web_infos': web_infos,
        'docker_ports_info': docker_ports_info,
        'is_docker': is_docker,
        'nuclei_results': nuclei_results,
        'epss_scores': epss_scores,
        'cve_guidelines': cve_guidelines,
        'epss_graph': histogram_path,
        'epss_chart': bar_chart_path

    }

    return render_template('result.html', result=last_scan_result)