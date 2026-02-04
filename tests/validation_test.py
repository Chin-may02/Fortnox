import requests

# Your API Endpoint
url = "http://127.0.0.1:5000/check_url"

print("--- Starting Input Validation Security Test ---\n")

# TEST 1: Send an Integer instead of a URL string
# (This tests "Invalid Data Types" from your PDF)
payload_bad_type = {"url": 12345}

try:
    print("Test 1: Sending Integer (12345)...")
    response = requests.post(url, json=payload_bad_type)
    print(f"Result: Status {response.status_code}")
    print(f"Response: {response.text}\n")
except Exception as e:
    print(f"Test 1 Failed: {e}\n")

# TEST 2: Send an Empty JSON object
# (This tests "Missing Fields" / Validation Logic)
payload_empty = {}

try:
    print("Test 2: Sending Empty Data...")
    response = requests.post(url, json=payload_empty)
    print(f"Result: Status {response.status_code}")
    print(f"Response: {response.text}\n")
except Exception as e:
    print(f"Test 2 Failed: {e}\n")

print("--- Test Finished ---")