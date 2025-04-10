import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"

def get_epss_scores(cve_list):
    if not cve_list:
        return {}

    results = {}
    for cve_id in cve_list:
        try:
            response = requests.get(f"{EPSS_API_URL}?cve={cve_id}")
            data = response.json()

            if data.get("data"):
                epss_data = data["data"][0]
                results[cve_id] = {
                    "epss_score": float(epss_data.get("epss", 0)),
                    "percentile": float(epss_data.get("percentile", 0))
                }
            else:
                results[cve_id] = {
                    "epss_score": 0.0,
                    "percentile": 0.0
                }
        except Exception as e:
            results[cve_id] = {
                "epss_score": 0.0,
                "percentile": 0.0,
                "error": str(e)
            }

    return results
