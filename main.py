import os
import dotenv
import socket
import json
import re


def parse_nginx_message(data: dict) -> dict:
    """
    Parse the nginx message for detailed information.
    Extracts key fields like client IP, method, request, response code, and timestamp.
    """
    # Regex to match the log format
    log_pattern = (
        r"(?P<client_ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "
        r"\"(?P<method>[A-Z]+) (?P<request>[^\s]+) HTTP/(?P<http_version>[^\"]+)\" "
        r"(?P<response_code>\d+) (?P<bytes>(?:\d+|-))"
    )
    
    message = data.get("message", "")
    match = re.match(log_pattern, message)
    
    if match:
        return match.groupdict()  # Extract matched groups into a dictionary
    else:
        return {
            "client_ip": None,
            "method": None,
            "request": None,
            "response_code": None,
            "timestamp": None,
        }


def socket_log_receive_callback(data: str) -> None:
    """
    Callback function to process data received from the Logstash socket.
    """
    try:
        data_json = json.loads(data)
        if data_json.get("log_type") == "nginx_access":
            print("Nginx Access Log Event:")
            print("Raw data:", data)
            print("Parsed JSON:", data_json)

            nginx_details = parse_nginx_message(data_json)
            print("Parsed nginx log details:")
            print(json.dumps(nginx_details, indent=4))
        else:
            print("Non-nginx log data received.")
            print(json.dumps(data_json, indent=4))
    except json.JSONDecodeError:
        print("Raw data received:", data)


def initiate_server(logstash_source_host: str, logstash_source_port: int) -> None:
    """
    Initiates a TCP server to receive data from Logstash.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Override the port if it's already in use
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        server_socket.bind((logstash_source_host, logstash_source_port))
        server_socket.listen(1)
        print(f"Listening on {logstash_source_host}:{logstash_source_port}")
        socket_connection, address = server_socket.accept()
        with socket_connection:
            print(f"Socket connected to {address}")
            while True:
                data = socket_connection.recv(1024)
                if not data:
                    break
                data = data.decode('utf-8')
                socket_log_receive_callback(data)


if __name__ == "__main__":
    dotenv.load_dotenv()

    LOGSTASH_SOURCE_HOST = os.getenv("LOGSTASH_SOURCE_HOST")
    LOGSTASH_SOURCE_PORT = os.getenv("LOGSTASH_SOURCE_PORT")
    if not LOGSTASH_SOURCE_HOST or not LOGSTASH_SOURCE_PORT:
        raise ValueError("Please specify LOGSTASH_SOURCE_HOST and LOGSTASH_SOURCE_PORT in .env file")

    logstash_source_host: str = LOGSTASH_SOURCE_HOST
    logstash_source_port: int = int(LOGSTASH_SOURCE_PORT)

    initiate_server(logstash_source_host, logstash_source_port)

