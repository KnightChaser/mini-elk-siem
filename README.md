# mini-opensearch-siem

A simple demonstration of SIEM for small NGINX web server, building a simple data pipeline with Filebeat, Logstash, AWS OpenSearch, and Python.

### Preview

![image](https://github.com/user-attachments/assets/1de38e6e-bd08-4397-9f2a-d67d920f1473)

![Screenshot from 2024-11-20 23-21-17](https://github.com/user-attachments/assets/e80e811e-a4ae-404f-af96-42cff0ff3991)

### Installation

Install `filebeat`, `logstash`, and `nginx` on your Linux system. Refer to the `/configuration` directory and configure those daemons with the given configuration files. You may adjust it if you want. Also, make an AWS OpenSearch instance which is accessible.

Create `.env` at the project directory and configure like below:

```.env
# Logstash configuration
LOGSTASH_SOURCE_HOST=127.0.0.1
LOGSTASH_SOURCE_PORT=9999

# OpenSearch configuration
OPENSEARCH_URL=[AMAZON OPENSEARCH URL]
OPENSEARCH_INDEX=[AMAZON OPEN SEARCH INDEX NAME]
OPENSEARCH_USERNAME=[YOUR OPENSEARCH USERNAME]
OPENSEARCH_PASSWORD=[YOUR OPENSEARCH PASSWORD]
```

Details can be found on the codes and configuration files, wouldn't be so complicated. Note that, this code is still an example, only for showing that this works and may give you an idea of operating SIEM with OpenSearch. You can freely develop, improve, and fix this for your own freely!
