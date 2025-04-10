import matplotlib.pyplot as plt
import os
from flask import current_app

BASE_STATIC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../static/epss_graphs"))

def generate_epss_histogram(epss_values, filename="sample.png"):
    if not epss_values:
        print("[⚠️] EPSS 값이 비어 있습니다. 히스토그램 생성 생략.")
        return None

    try:
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../static/epss_graphs"))
        os.makedirs(folder, exist_ok=True)

        filename_only = os.path.basename(filename)
        save_path = os.path.join(BASE_STATIC_PATH, filename_only)  # 절대 경로로 저장
        plt.figure(figsize=(8, 4))
        plt.hist(epss_values, bins=10, range=(0, 1), color="#00b894", edgecolor="black")
        plt.title("EPSS Score Distribution")
        plt.xlabel("EPSS Score")
        plt.ylabel("CVE Count")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(save_path)
        print(f"[✅] EPSS 히스토그램 저장됨: {save_path}")

        return f"epss_graphs/{filename_only}"  # 🔥 HTML에서 쓸 상대 경로만 반환
    except Exception as e:
        print(f"[❌] EPSS 히스토그램 생성 오류: {e}")
        return None
    finally:
        plt.close()

def generate_epss_chart(epss_scores, filename="epss_top25.png"):
    if not epss_scores:
        print("[⚠️] EPSS 점수 없음. Top25 차트 생략.")
        return None

    try:
        sorted_epss = sorted(
            [(cve, info["epss_score"]) for cve, info in epss_scores.items() if "epss_score" in info],
            key=lambda x: x[1],
            reverse=True
        )

        if not sorted_epss:
            print("[⚠️] EPSS 점수가 있는 CVE가 없음.")
            return None

        top = sorted_epss[:25]
        cve_ids = [item[0] for item in top]
        scores = [item[1] for item in top]
        filename_only = os.path.basename(filename)

        # ✅ 저장 경로 결정
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../static/epss_graphs"))
        os.makedirs(folder, exist_ok=True)
        save_path = os.path.join(folder, filename_only)

        plt.figure(figsize=(10, 5))
        plt.bar(cve_ids, scores, color="#ff7675", edgecolor="black")
        plt.xticks(rotation=45, ha='right')
        plt.title("Top 25 CVEs by EPSS Score")
        plt.xlabel("CVE ID")
        plt.ylabel("EPSS Score")
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        print(f"[✅] EPSS Top25 차트 저장됨: {save_path}")

        # ✅ 상대 경로 반환 (Flask 템플릿용)
        return f"epss_graphs/{filename_only}"

    except Exception as e:
        print(f"[❌] EPSS Top10 차트 생성 오류: {e}")
        return None
    finally:
        plt.close()