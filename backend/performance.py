import requests
import time
import statistics

API_URL = "http://127.0.0.1:8000/predict"

urls = [
    "https://leetcode.com",
    "https://spotify.com",
    "https://github.com",
    "https://google.com",
    "https://example.com"
]

times = []

for url in urls:
    start = time.perf_counter()

    response = requests.post(
        API_URL,
        json={"url": url},
        timeout=10
    )

    end = time.perf_counter()

    elapsed = (end - start) * 1000
    times.append(elapsed)

    print(f"{url}")
    print(f"Status: {response.status_code}")
    print(f"Response time: {elapsed:.2f} ms")
    print(f"Response: {response.json()}")
    print("-" * 50)

print("\n===== PERFORMANCE RESULT =====")
print(f"Requests: {len(times)}")
print(f"Average: {statistics.mean(times):.2f} ms")
print(f"Minimum: {min(times):.2f} ms")
print(f"Maximum: {max(times):.2f} ms")