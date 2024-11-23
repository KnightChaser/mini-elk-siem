# opensearch.py
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests.auth import HTTPBasicAuth
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

# Retrieve OpenSearch configuration from .env
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX")
OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")

def create_index_with_mapping(client: OpenSearch, index_name: str) -> None:
    """
    Create an OpenSearch index with a predefined mapping.
    
    Args:
        client (OpenSearch): The OpenSearch client.
        index_name (str): The name of the index.
    """
    mapping = {
      "mappings": {
        "properties": {
          "timestamp": {
            "type": "date",
            "format": "yyyy/MM/dd HH:mm:ss Z"
          },
          "client_ip": {
            "type": "ip"
          },
          "method": {
            "type": "keyword"
          },
          "request": {
            "type": "text"
          },
          "attack_type": {
            "type": "object",
            "properties": {
              "type": {
                "type": "keyword"
              },
              "sub_attack_type": {
                "type": "keyword"
              }
            }
          },
          "status": {
            "type": "keyword"
          }
        }
      }
    }


    try:
        if not client.indices.exists(index=index_name):
            response = client.indices.create(index=index_name, body=mapping)
            print(f"Index {index_name} created with mapping: {response}")
        else:
            print(f"Index {index_name} already exists.")
    except Exception as e:
        print(f"Failed to create index: {e}")

# Initialize OpenSearch client
def get_opensearch_client() -> OpenSearch:
    """
    Create and return an OpenSearch client with dynamic SSL configuration.
    """
    # Fetch environment variables
    OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
    OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")
    OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "True").lower() in ["true", "1", "t"]

    # Validate configuration
    if not OPENSEARCH_URL or not OPENSEARCH_USERNAME or not OPENSEARCH_PASSWORD:
        raise ValueError("OpenSearch configuration is missing in the environment variables")

    # Determine SSL settings based on the URL scheme
    use_ssl = OPENSEARCH_URL.startswith("https")
    verify_certs = use_ssl and OPENSEARCH_VERIFY_CERTS  # Verify certs only if using SSL and verification is enabled

    # Log the connection details for debugging
    protocol = "https" if use_ssl else "http"
    host = OPENSEARCH_URL.split("://")[1].split(":")[0]
    port = OPENSEARCH_URL.split(":")[-1]
    print(f"Connecting to OpenSearch: {protocol}://{host}:{port}")

    # Initialize the OpenSearch client
    client = OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=HTTPBasicAuth(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        connection_class=RequestsHttpConnection,
    )
    return client
def push_to_opensearch(client, data) -> None:
    """
    Push data to the OpenSearch index.

    Args:
        client (OpenSearch): The OpenSearch client.
        data (dict): The data to insert.
    """
    try:
        response = client.index(index=OPENSEARCH_INDEX, body=data)
        print(f"Document added to OpenSearch: {response['_id']}")
    except Exception as e:
        print(f"Failed to push data to OpenSearch: {e}")

