# mini-opensearch-siem

A simple demonstration of SIEM for small NGINX web server, building a simple data pipeline with Filebeat, Logstash, OpenSearch(local installation or AWS instance), and Python.

### Preview

![image](https://github.com/user-attachments/assets/2c46659f-2e04-483c-9085-f8dad97c412d)

![image](https://github.com/user-attachments/assets/b68d73ad-829e-40b7-a383-00e15fdab569)

### Installation

Install `filebeat`, `logstash`, and `nginx` on your Linux system. Refer to the `/configuration` directory and configure those daemons with the given configuration files. You may adjust it if you want. Also, make an OpenSearch instance which is accessible.

Create `.env` at the project directory and configure like below:

```env
# Logstash configuration
LOGSTASH_SOURCE_HOST=127.0.0.1
LOGSTASH_SOURCE_PORT=9999

# OpenSearch configuration
OPENSEARCH_URL=https://127.0.0.1:9200
OPENSEARCH_INDEX=nginx-logs
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=OpenSearch2024##
OPENSEARCH_VERIFY_CERTS=False
```

- If you're using AWS OpenSearch, set `OPENSEARCH_VERIFY_CERTS` to `true` since AWS provides necessary web security configurations such as web certificates.
- If you're using local installation of OpenSearch, adjust that option dynamically depending on whether you manually configured certificates or not.

Details can be found on the codes and configuration files, wouldn't be so complicated. Note that, this code is still an example, only for showing that this works and may give you an idea of operating SIEM with OpenSearch. You can freely develop, improve, and fix this for your own freely!
