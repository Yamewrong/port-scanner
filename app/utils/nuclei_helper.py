import subprocess
import json
import os

def run_nuclei_scan(target, output_path="nuclei_output.json"):
    try:
        command = [
            "nuclei", "-u", target,
            "-json-export", output_path
        ]
        # ✅ 10초 타임아웃 설정
        subprocess.run(command, check=True, timeout=10)

        if not os.path.exists(output_path):
            return [{"template": "Nuclei 실패", "info": {"name": "결과 없음", "severity": "info"}, "matched": "파일 없음"}]

        with open(output_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        # ✅ 결과가 비어있으면 fallback
        if not lines:
            return [{"template": "탐지 없음", "info": {"name": "Nuclei 결과 없음", "severity": "info"}, "matched": target}]

        results = []
        for line in lines:
            try:
                obj = json.loads(line)
                if isinstance(obj.get("info"), str):
                    obj["info"] = json.loads(obj["info"])
                if "info" not in obj or not isinstance(obj["info"], dict):
                    obj["info"] = {"name": "정보 없음", "severity": "unknown"}
                results.append(obj)
            except Exception:
                continue
        return results

    except subprocess.TimeoutExpired:
        return [{
            "template": "탬플릿 시간초과",
            "info": {"name": "실행 시간 초과", "severity": "error"},
            "matched": target
        }]
    except subprocess.CalledProcessError as e:
        return [{
            "template": "탬플릿 오류",
            "info": {"name": "탐지 실패", "severity": "error"},
            "matched": str(e)
        }]