#!/bin/bash

# Check if NGINX is installed
if dpkg -l | grep -q nginx; then
    echo "NGINX is installed. Proceeding with configuration..."
else
    echo "NGINX is not installed. Please install it first."
    exit 1
fi

# Define server block configuration for SQL injection detection
SERVER_BLOCK_CONF="/etc/nginx/sites-available/sql_injection"
SERVER_BLOCK_LINK="/etc/nginx/sites-enabled/sql_injection"
LOG_PATH="/var/log/nginx/sql_injection.log"

# Create a new server block configuration
echo "Creating server block configuration for SQL injection detection..."
cat <<EOL > "$SERVER_BLOCK_CONF"
server {
    listen 80;
    server_name localhost;

    access_log $LOG_PATH;

    location / {
        return 200 "Welcome to the vulnerable web server!\\n";
    }

    location /search {
        if (\$arg_q ~* ".*('|;|--|\\b(UNION|SELECT|INSERT|DROP|UPDATE|DELETE)\\b).*") {
            return 403 "SQL Injection attempt detected!";
        }
        return 200 "Searching for: \$arg_q\\n";
    }
}
EOL

# Create the log file if it doesn't exist
echo "Ensuring log file exists..."
sudo touch "$LOG_PATH"
sudo chown www-data:www-data "$LOG_PATH"

# Enable the new server block
echo "Enabling server block..."
sudo ln -sf "$SERVER_BLOCK_CONF" "$SERVER_BLOCK_LINK"

# Disable the default server block
if [ -f /etc/nginx/sites-enabled/default ]; then
    echo "Disabling default server block..."
    sudo rm /etc/nginx/sites-enabled/default
fi

# Test NGINX configuration
echo "Testing NGINX configuration..."
if sudo nginx -t; then
    echo "NGINX configuration is valid."
else
    echo "NGINX configuration test failed. Check your configuration."
    exit 1
fi

# Restart NGINX to apply changes
echo "Restarting NGINX..."
sudo systemctl restart nginx

echo "NGINX is configured for SQL injection detection."

