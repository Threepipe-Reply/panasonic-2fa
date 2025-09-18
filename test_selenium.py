from selenium import webdriver
from selenium.webdriver.common.by import By
import time

def test_ui_flow():
    driver = webdriver.Chrome()  # Requires chromedriver
    
    try:
        # Test home page
        driver.get("http://localhost:5000")
        assert "Panasonic 2FA" in driver.title
        
        # Test login page
        driver.get("http://localhost:5000/login")
        username = driver.find_element(By.CLASS_NAME, "username")
        password = driver.find_element(By.NAME, "password")
        
        username.send_keys("testuser")
        password.send_keys("testpass123")
        
        submit = driver.find_element(By.NAME, "submit")
        submit.click()
        
        time.sleep(1)
        # Should stay on login page (invalid credentials)
        assert "login" in driver.current_url.lower()
        
    finally:
        driver.quit()

if __name__ == "__main__":
    test_ui_flow()