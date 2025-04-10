from flask import Blueprint, render_template, send_file
import io
from app.routes.analysis import last_scan_result

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/download')
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