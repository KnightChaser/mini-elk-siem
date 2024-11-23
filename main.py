# main.py
import os
import dotenv
import socket
import json
import re
import signal
import urllib.parse  # Added for URL decoding
import logging
from datetime import datetime
from json import JSONDecodeError
from termcolor import colored
from detectors import detect_attack_type
from opensearch import create_index_with_mapping, get_opensearch_client, push_to_opensearch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("server.log")
    ]
)

server_socket = None  # Global reference to the server socket for cleanup

def parse_nginx_message(data: dict) -> dict:
    """
    Parse the nginx message for detailed information.
    Extracts key fields like client IP, method, request, response code, and timestamp.
    """
    message = data.get("message", "")
    log_pattern = (
        r"^(?P<client_ip>[^\s]+) - - \[(?P<timestamp>[^\]]+)\] "
        r"\"(?P<method>[A-Z]+) (?P<request>[^\s]+) HTTP/[^\"]+\" "
        r"(?P<response_code>\d+) (?P<bytes>(?:\d+|-))"
    )

    match = re.match(log_pattern, message)
    if match:
        # Extract matched groups safely
        return {
            "client_ip": match.group("client_ip"),
            "timestamp": match.group("timestamp"),
            "method": match.group("method"),
            "request": match.group("request"),
            "response_code": match.group("response_code"),
        }

    # Fallback for invalid formats
    logging.warning(f"Failed to parse nginx message: {message}")
    return {
        "client_ip": None,
        "timestamp": None,
        "method": None,
        "request": None,
        "response_code": None,
    }

def print_suspicious(timestamp: str, client_ip: str, method: str, request: str, attack_type: dict) -> None:
    """
    Print suspicious requests in red color.
    """
    output = (
        f"[{timestamp}] [{client_ip}] [{method}] [{request}] => "
        f"suspicious of [{attack_type['type']} - {attack_type['sub_attack_type']}]"
    )
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
        logging.info("Server socket closed.")

def signal_handler(sig, frame):
    """
    Handle termination signals to cleanup resources.
    """
    logging.info("Graceful shutdown initiated...")
    cleanup_server()
    exit(0)

def socket_log_receive_callback(data: str) -> None:
    """
    Callback function to process data received from the TCP socket.
    Detects suspicious activity, logs the request, and pushes data to OpenSearch.
    """
    try:
        logging.info(f"Raw data received: {data}")

        # Parse incoming data as JSON
        data_json = json.loads(data)

        # Identify if the log is from nginx access based on 'source_type'
        source_type = data_json.get("source_type")
        if source_type != "nginx":
            logging.warning("Non-nginx log data received.")
            return

        nginx_details = parse_nginx_message(data_json)

        # Extract relevant fields
        timestamp = nginx_details.get("timestamp")
        if not timestamp:
            logging.error("Missing timestamp in log.")
            return

        timestamp = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        timestamp = timestamp.strftime("%Y/%m/%d %H:%M:%S %z")  # Convert to specified format
        client_ip = nginx_details.get("client_ip") if nginx_details.get("client_ip") else None
        method = nginx_details.get("method") if nginx_details.get("method") else None
        request = nginx_details.get("request")

        if not request:
            logging.error("Invalid request format received.")
            return

        # Decode the URL-encoded request
        decoded_request = urllib.parse.unquote_plus(request)
        attack_type = detect_attack_type(decoded_request)

        # Determine log status (benign/suspicious)
        status = "suspicious" if attack_type else "benign"
        logging.info(f"Log Status: {status}")

        if attack_type:
            print_suspicious(timestamp, client_ip, method, decoded_request, attack_type)
        else:
            print_benign(timestamp, client_ip, method, decoded_request)

        # Prepare data for OpenSearch
        opensearch_data = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "request": decoded_request,
            "attack_type": attack_type if attack_type else {},
            "status": status,
        }

        # Push data to OpenSearch
        opensearch_client = get_opensearch_client()
        push_to_opensearch(opensearch_client, opensearch_data)

    except JSONDecodeError as e:
        logging.error(f"JSON decoding error: {e}")
        logging.error(f"Unparsed data: {data}")
    except Exception as e:
        logging.exception(f"Exception occurred in callback: {e}")

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
        logging.info(f"Listening on {logstash_source_host}:{logstash_source_port}")

        while True:
            socket_connection, address = server_socket.accept()
            logging.info(f"Socket connected to {address}")
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
            logging.info(f"Connection to {address} closed")
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
    create_index_with_mapping(get_opensearch_client(), "nginx-logs")
    main()

