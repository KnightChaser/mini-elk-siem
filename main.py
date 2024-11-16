import os
import dotenv
import socket
import json
import re

def parse_snort_message(message: str) -> dict:
    """Parse the Snort message for detailed information."""
    # Regex pattern to extract information, including Classification
    pattern = r"(?P<timestamp>[\d/:-]+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<alert>[^\[\]]+)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>[^\]]+)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>[A-Z]+)\}\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
    match = re.search(pattern, message)
    if match:
        return match.groupdict()
    return {}

def socket_log_receive_callback(data: str) -> None:
    try:
        data_json = json.loads(data)
        if data_json.get("log_type") == "snort_alert":
            print("Snort Event Detected:")
            snort_details = parse_snort_message(data_json.get("message", ""))
            processed_data = {
                "timestamp": data_json.get("@timestamp"),
                "alert_details": snort_details,
                "classification": snort_details.get("classification", "Unknown"),
                "agent": data_json.get("agent", {}),
                "host": data_json.get("host", {}),
                "log_path": data_json.get("log", {}).get("file", {}).get("path"),
                "raw_message": data_json.get("event", {}).get("original"),
            }
            print(json.dumps(processed_data, indent=4))
        else:
            print("Non-Snort log data received.")
            print(json.dumps(data_json, indent=4))
    except json.JSONDecodeError:
        print("Raw data received:", data)


def initiate_server(logstash_source_host: str, logstash_source_port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Override the port if it's already in use
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # Initiate the session
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

    logstash_source_host:str = LOGSTASH_SOURCE_HOST
    logstash_source_port:int = int(LOGSTASH_SOURCE_PORT)

    initiate_server(logstash_source_host, logstash_source_port)
