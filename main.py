# main.py
import os
import dotenv
import socket
import json
import re
import signal
from detectors import detect_attack_type
from termcolor import colored
from json import JSONDecodeError

server_socket = None  # Global reference to the server socket for cleanup

def parse_nginx_message(data: dict) -> dict:
    """
    Parse the nginx message for detailed information.
    Extracts key fields like client IP, method, request, response code, and timestamp.
    Personal note: It would be improved in case of using filebeat nginx service since it provides better metadata.
    """
    log_pattern = (
        r"(?P<client_ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "
        r"\"(?P<method>[A-Z]+) (?P<request>[^\s]+) HTTP/(?P<http_version>[^\"]+)\" "
        r"(?P<response_code>\d+) (?P<bytes>(?:\d+|-))"
    )

    message = data.get("message", "")
    match = re.match(log_pattern, message)

    if match:
        return match.groupdict()
    else:
        return {
            "client_ip": None,
            "timestamp": None,
            "method": None,
            "request": None,
            "response_code": None,
        }


def print_suspicious(timestamp: str, client_ip: str, method: str, request: str, attack_type: str) -> None:
    """
    Print suspicious requests in red color.
    """
    output = f"[{timestamp}] [{client_ip}] [{method}] [{request}] => suspicious of [{attack_type}]"
    print(colored(output, "red"))


def print_benign(timestamp: str, client_ip: str, method: str, request: str) -> None:
    """
    Print benign requests in green color.
    """
    output = f"[{timestamp}] [{client_ip}] [{method}] [{request}]"
    print(colored(output, "green"))

def cleanup_server() -> None:
    """
    Cleanup server resources on shutdown.
    """
    global server_socket
    if server_socket:
        server_socket.close()
        print("Server socket closed.")


def signal_handler(sig, frame):
    """
    Handle termination signals to cleanup resources.
    """
    print("\nGraceful shutdown initiated...")
    cleanup_server()
    exit(0)

def socket_log_receive_callback(data: str) -> None:
    """
    Callback function to process data received from the TCP socket.
    Detects suspicious activity and logs the request.
    """
    try:
        # Debug raw data for troubleshooting
        print(f"Raw data received: {data}")

        # Attempt to parse data as JSON
        data_json = json.loads(data)

        # Identify if the log is from nginx access using event.dataset
        event_dataset = data_json.get("event", {}).get("dataset")
        if event_dataset != "nginx.access":
            print("Non-nginx log data received.")
            return  # Early exit if log type is not nginx_access

        nginx_details = parse_nginx_message(data_json)

        # Extract relevant fields
        timestamp = nginx_details.get("timestamp")
        client_ip = nginx_details.get("client_ip")
        method = nginx_details.get("method")
        request = nginx_details.get("request")

        if not request:
            print("Invalid request format received.")
            return  # Early exit if request is missing

        # Detect suspicious activity
        attack_type = detect_attack_type(request)
        if attack_type:
            assert timestamp and client_ip and method and request and attack_type, "One or more fields missing"
            print_suspicious(timestamp, client_ip, method, request, attack_type)
        else:
            assert timestamp and client_ip and method and request, "One or more fields missing"
            print_benign(timestamp, client_ip, method, request)

    except JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        print(f"Unparsed data: {data}")
    except Exception as e:
        print(f"Exception occurred in callback: {e}")


def initiate_server(logstash_source_host: str, logstash_source_port: int) -> None:
    """
    Initiates a TCP server to receive data from Filebeat or Logstash.
    """
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    try:
        server_socket.bind((logstash_source_host, logstash_source_port))
        server_socket.listen(1)
        print(f"Listening on {logstash_source_host}:{logstash_source_port}")

        while True:
            socket_connection, address = server_socket.accept()
            print(f"Socket connected to {address}")
            with socket_connection:
                buffer = ""
                while True:
                    data = socket_connection.recv(1024)
                    if not data:
                        break
                    buffer += data.decode('utf-8')

                    # Process buffer iteratively for JSON objects
                    while True:
                        try:
                            # Attempt to parse a single JSON object
                            parsed_data, idx = json.JSONDecoder().raw_decode(buffer)
                            socket_log_receive_callback(json.dumps(parsed_data))
                            buffer = buffer[idx:].lstrip()  # Remove processed data
                        except JSONDecodeError:
                            break  # Wait for more data if JSON is incomplete
            print(f"Connection to {address} closed")
    finally:
        cleanup_server()

def main():
    dotenv.load_dotenv()

    LOGSTASH_SOURCE_HOST = os.getenv("LOGSTASH_SOURCE_HOST")
    LOGSTASH_SOURCE_PORT = os.getenv("LOGSTASH_SOURCE_PORT")
    if not LOGSTASH_SOURCE_HOST or not LOGSTASH_SOURCE_PORT:
        raise ValueError("Please specify LOGSTASH_SOURCE_HOST and LOGSTASH_SOURCE_PORT in .env file")

    try:
        logstash_source_port = int(LOGSTASH_SOURCE_PORT)
    except ValueError:
        raise ValueError("LOGSTASH_SOURCE_PORT must be an integer")

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    initiate_server(LOGSTASH_SOURCE_HOST, logstash_source_port)


if __name__ == "__main__":
    main()

