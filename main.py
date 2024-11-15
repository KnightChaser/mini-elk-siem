import os
import dotenv
import socket
import json

def socket_log_receive_callback(data: str) -> None:
    # Just print the data with pretty JSON format
    data_json = json.loads(data)
    print(json.dumps(data_json, indent=4))

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
