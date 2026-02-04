import requests
import time

# REPLACE with your actual local API URL (e.g., http://127.0.0.1:5000/predict)
url = "http://127.0.0.1:5000/check_url"
data = {"url": "http://google.com"}  # A safe URL to test

print("Starting Stress Test...")
start_time = time.time()

# Send 50 requests as fast as possible
for i in range(50):
    try:
        response = requests.post(url, json=data)
        print(f"Request {i+1}: Status {response.status_code}")
    except Exception as e:
        print(f"Request {i+1}: Failed ({e})")

end_time = time.time()
print(f"\nTest Finished in {end_time - start_time:.2f} seconds")