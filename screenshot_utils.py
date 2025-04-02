from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import requests
import os

def capture_web_info(ip, save_dir='static/captures'):
    urls = [f"http://{ip}", f"https://{ip}"]
    os.makedirs(save_dir, exist_ok=True)

    results = []

    for url in urls:
        try:
            # 웹 페이지 접속 및 헤더 추출
            headers = {}
            try:
                res = requests.get(url, timeout=5, verify=False)
                headers = res.headers
                soup = BeautifulSoup(res.text, 'html.parser')
                title = soup.title.string.strip() if soup.title else "제목 없음"
            except:
                title = "제목 없음"

            # Selenium 설정
            options = Options()
            options.headless = True
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            driver.set_window_size(1280, 720)

            # 스크린샷 파일명 구성
            protocol = url.split('//')[0]
            filename = f"{ip.replace('.', '_')}_{protocol}.png"
            image_path = os.path.join(save_dir, filename)

            driver.get(url)
            driver.save_screenshot(image_path)
            driver.quit()

            # 결과 저장
            results.append({
                'url': url,
                'title': title,
                'server': headers.get('Server', '알 수 없음'),
                'image': filename  # 파일명만 반환!
            })
        except Exception as e:
            continue

    return results
