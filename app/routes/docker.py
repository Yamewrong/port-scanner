import os
import subprocess
import json
import time
import re
import urllib.parse
from flask import Blueprint, render_template, request, jsonify, abort
from app.utils.epss_helper import get_epss_scores
from app.utils.epss_graph_helper import generate_epss_histogram, generate_epss_chart
from app.utils.nuclei_helper import run_nuclei_scan
from app.utils.ansible_helper import (
    check_docker_installed,
    scan_docker_image_with_trivy,
    parse_trivy_output_from_json,
    get_docker_images
)

docker_bp = Blueprint('docker', __name__)

@docker_bp.route("/list_images", methods=["POST"])
def list_images():
    pem_file = request.files.get('pem_file')
    remote_ip = request.form.get('remote_ip', '').strip()
    remote_user = request.form.get('remote_user', '').strip()

    if not pem_file or not remote_ip or not remote_user:
        return jsonify({"error": "모든 정보를 입력해 주세요."})

    try:
        pem_content = pem_file.read().decode('utf-8')
        image_list = get_docker_images(remote_ip, remote_user, pem_content)
        return jsonify({"images": image_list})
    except Exception as e:
        print(f"[ERROR] 이미지 목록 가져오기 실패: {e}")
        return jsonify({"images": []})


@docker_bp.route('/check_docker', methods=['POST'])
def check_docker():
    pem_file = request.files.get('pem_file')
    remote_ip = request.form.get('remote_ip', '').strip()
    remote_user = request.form.get('remote_user', '').strip()

    if not pem_file or not remote_ip or not remote_user:
        return render_template('index.html', error="모든 정보를 입력해 주세요.", prev_ip=remote_ip, prev_user=remote_user)

    try:
        pem_content = pem_file.read().decode('utf-8')
        is_installed = check_docker_installed(remote_ip, remote_user, pem_content)

        if is_installed:
            message = "✅ Docker가 설치되어 있습니다."
            docker_images = get_docker_images(remote_ip, remote_user, pem_content)
        else:
            message = "❌ Docker가 설치되어 있지 않습니다."
            docker_images = []

    except Exception as e:
        print(f"[ERROR] Docker 확인 중 문제 발생: {e}")
        message = "⚠️ Docker 확인 중 오류가 발생했습니다."
        docker_images = []

    print(f"[DEBUG] 전달되는 docker_images: {docker_images}")

    return render_template(
        'index.html',
        docker_result=message,
        docker_images=docker_images,
        docker_installed=is_installed,
        prev_ip=remote_ip,
        prev_user=remote_user
    )


@docker_bp.route('/docker_vulns/<path:image_name>')
def docker_vulns(image_name):
    from urllib.parse import unquote
    decoded_image = unquote(image_name)
    safe_image_name = decoded_image.replace("/", "_").replace(":", "_")

    trivy_path = None
    for base_path in ["trivy_reports", "saved_reports"]:
        candidate_path = os.path.join(base_path, f"{safe_image_name}.json")
        if os.path.exists(candidate_path):
            trivy_path = candidate_path
            break

    if not trivy_path:
        return abort(404)

    with open(trivy_path, encoding="utf-8") as f:
        data = json.load(f)

    severity = request.args.get("severity")
    all_vulns = []
    for result in data.get("Results", []):
        all_vulns.extend(result.get("Vulnerabilities", []))
    if severity:
        all_vulns = [v for v in all_vulns if v.get("Severity", "").lower() == severity.lower()]

    page = int(request.args.get("page", 1))
    per_page = 10
    total_pages = (len(all_vulns) + per_page - 1) // per_page
    paginated = all_vulns[(page - 1) * per_page: page * per_page]

    epss_scores = get_epss_scores([v["VulnerabilityID"] for v in paginated if "VulnerabilityID" in v])
    guidelines = generate_guidelines_from_vulns(paginated, epss_scores)
    for v in paginated:
        if v.get("VulnerabilityID") in guidelines:
            v["Guideline"] = guidelines[v["VulnerabilityID"]]

    return render_template(
        "docker_vulns.html",
        image=decoded_image,
        vulns=paginated,
        page=page,
        total_pages=total_pages,
        severity=severity
    )

@docker_bp.route("/scan_image", methods=["POST"])
def scan_image():
    start_time = time.time()
    scan_duration = round(time.time() - start_time, 2)
    remote_ip = request.form.get("remote_ip")
    remote_user = request.form.get("remote_user")
    image_name = request.form.get("docker_image")
    pem_file = request.files.get("pem_file")

    if not (remote_ip and remote_user and image_name and pem_file):
        return render_template("index.html", error="모든 입력 항목을 채워주세요.", prev_ip=remote_ip, prev_user=remote_user)

    pem_content = pem_file.read().decode("utf-8")
    json_path = scan_docker_image_with_trivy(remote_ip, remote_user, pem_content, image_name)

    if not os.path.exists(json_path):
        return render_template("index.html", error="Trivy 리포트 생성 실패", prev_ip=remote_ip, prev_user=remote_user)

    with open(json_path, "r", encoding="utf-8") as f:
        _ = json.load(f)
    trivy_json_vulns = parse_trivy_output_from_json(json_path)
    cve_list = [v["VulnerabilityID"] for v in trivy_json_vulns if "VulnerabilityID" in v]
    epss_scores = get_epss_scores(cve_list)
    guidelines = generate_guidelines_from_vulns(trivy_json_vulns, epss_scores)
    epss_vals = [score['epss_score'] for score in epss_scores.values()]
    image_safe = image_name.replace('/', '_').replace(':', '_')
    epss_graph_path = generate_epss_histogram(epss_vals, filename=f"{image_safe}_hist.png")
    epss_chart_path = generate_epss_chart(epss_scores, filename=f"{image_safe}_top25.png")

    result = {
        "ip": image_name,
        "scan_time": scan_duration,
        "warnings": [],
        "shodan_info": [],
        "nuclei_results": [],
        "epss_scores": epss_scores,
        "cve_warnings": [],
        "cve_guidelines": guidelines,
        "web_infos": [],
        "docker_ports_info": {},
        "trivy_json_results": trivy_json_vulns,
        "epss_graph": epss_graph_path,
        "epss_chart": epss_chart_path
    }
    return render_template(
        "result.html",
        result=result,
        image=image_name
    )

def generate_guidelines_from_vulns(vulns, epss_map):
    guidelines = {}
    for v in vulns:
        cve_id = v.get("VulnerabilityID")
        severity = v.get("Severity", "UNKNOWN")
        title = v.get("Title") or "정보 없음"
        epss_info = epss_map.get(cve_id, {})
        epss_score = round(epss_info.get("epss_score", 0), 2)
        url = v.get("PrimaryURL", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        fixed = v.get("FixedVersion")

        guide = f"""<strong>[{severity}] {cve_id} (EPSS: {epss_score})</strong><br>
        <ul>
            <li>※ 주요 위험: {title}</li>
            {f"<li>🔒 <strong>보안 패치 버전:</strong> {fixed}</li>" if fixed else ""}
            <li>✅ 최신 버전으로 업그레이드 권장 및 네트워크 접근 제어 필요</li>
            <li>🔗 <a href=\"{url}\" target=\"_blank\">자세히 보기</a></li>
        </ul>
        """
        guidelines[cve_id] = guide
    return guidelines
