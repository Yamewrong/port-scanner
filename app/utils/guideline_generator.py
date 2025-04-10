def generate_guidelines_from_vulns(vulns, epss_map):
    guidelines = {}
    for v in vulns:
        cve_id = v.get("VulnerabilityID")
        severity = v.get("Severity")
        title = v.get("Title") or "정보 없음"
        epss_info = epss_map.get(cve_id, {})
        epss_score = round(epss_info.get("epss_score", 0), 2)

        guide = f"[{severity}] {cve_id} (EPSS: {epss_score})\n"
        guide += f"※ 주요 위험: {title}\n\n"
        if v.get("FixedVersion"):
            guide += f"- 🔒 보안 패치 버전: {v['FixedVersion']}\n"
        guide += "- ✅ 최신 버전으로 업그레이드 권장 및 네트워크 접근 제어 필요\n"
        guide += f"- 🔗 자세히 보기: {v.get('PrimaryURL', 'N/A')}\n"

        guidelines[cve_id] = guide
    return guidelines
