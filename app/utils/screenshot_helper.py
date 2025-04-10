from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import time

def take_screenshot(url, save_path="screenshot.png"):
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(2)  # 페이지 로딩 대기

        # 저장할 디렉토리 없으면 생성
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        driver.save_screenshot(save_path)
        driver.quit()
        return True
    except Exception as e:
        return {"error": str(e)}
